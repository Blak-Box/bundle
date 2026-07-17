// Command bundle is the CLI bridge to the BlakBox bundle crypto core.
//
// It is the tool the offline update chain (and, later, the companion exporter
// and signed egress) shell out to so that every artifact crossing the air gap
// is signed and verified through ONE library — the same ECDSA-P384-over-DSSE /
// in-toto attestation the whole product is built on. It replaces the ad-hoc
// `openssl pkeyutl` Ed25519 detached signatures the update chain used before.
//
// Three subcommands:
//
//	bundle keygen  -out-dir DIR -name NAME
//	    Generate a P-384 release keypair: NAME.key (PKCS#8 PEM, 0400),
//	    NAME.pub (SPKI PEM), NAME.fingerprint (the trust identity, printed
//	    on the manifest sheet and read out-of-band to customers).
//
//	bundle attest  -key KEY.pem -artifact FILE [-predicate manifest.json]
//	               [-predicate-type TYPE] [-subject-name NAME] -out ENV.json
//	    Produce an in-toto v1 Statement whose subject is the SHA-384 digest
//	    of FILE, sign it into a DSSE envelope with the P-384 key, write ENV.json.
//
//	bundle verify  -anchor PUB.pem [-anchor PUB2.pem ...] -artifact FILE
//	               -in ENV.json [-predicate-type TYPE] [-subject-name NAME]
//	    Verify the DSSE envelope against the PINNED anchor key(s), then RE-BIND:
//	    recompute SHA-384(FILE) and require it to equal the signed subject
//	    digest. A good signature over a statement that describes a DIFFERENT
//	    artifact is rejected. Exit 0 = good, 1 = verification FAILED, 2 = usage.
//
// Every algorithm on the verify path (ECDSA P-384, SHA-384) is in the FIPS
// 140-3 validated Go module; build with GOFIPS140=v1.0.0 for the appliance.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/blak-box/bundle"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
)

// subjectDigestAlg is the digest algorithm bound in the in-toto subject and
// re-checked at verify time. SHA-384 matches decision D5 (the same hash the
// ECDSA-P384 signature is computed over) — one hash strength end to end.
const subjectDigestAlg = "sha384"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "attest":
		err = runAttest(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "fingerprint":
		err = runFingerprint(os.Args[2:])
	case "version":
		err = runVersion(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "bundle: unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "bundle: %v\n", err)
		// A usage error exits 2; anything else (including a failed
		// verification) exits 1 so callers can distinguish "you invoked
		// me wrong" from "the artifact is not trustworthy".
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func usage() {
	fmt.Fprint(os.Stderr, `bundle — BlakBox bundle-format CLI (P-384 / DSSE / in-toto)

Usage:
  bundle keygen -out-dir DIR -name NAME
  bundle attest -key KEY.pem -artifact FILE [-predicate manifest.json]
                [-predicate-type TYPE] [-subject-name NAME] -out ENV.json
  bundle verify -anchor PUB.pem [-anchor ...] -artifact FILE -in ENV.json
                [-predicate-type TYPE] [-subject-name NAME]
  bundle fingerprint (-key KEY.pem | -pub PUB.pem)
  bundle version

Exit codes: 0 ok · 1 verification failed · 2 usage error
`)
}

// ── version ─────────────────────────────────────────────────────────────

// runVersion prints build provenance, including the GOFIPS140 build setting.
// The appliance ships in FIPS mode and its verify path MUST run through the
// FIPS 140-3 validated module (CMVP #5247), which is selected at BUILD time
// (GOFIPS140=v1.0.0). That property is otherwise invisible at runtime, so we
// surface it here: `bundle version` on the shipped binary must report
// fips140=v1.0.0. Factory imaging and release provenance can assert on it.
func runVersion(argv []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	if err := fs.Parse(argv); err != nil {
		return errUsage
	}
	fips := "off"
	goVersion := "unknown"
	var goos, goarch, vcs string
	if bi, ok := debug.ReadBuildInfo(); ok {
		goVersion = bi.GoVersion
		for _, s := range bi.Settings {
			switch s.Key {
			case "GOFIPS140":
				if s.Value != "" {
					fips = s.Value
				}
			case "GOOS":
				goos = s.Value
			case "GOARCH":
				goarch = s.Value
			case "vcs.revision":
				vcs = s.Value
			}
		}
	}
	fmt.Printf("bundle CLI\n")
	fmt.Printf("  go:       %s\n", goVersion)
	fmt.Printf("  platform: %s/%s\n", goos, goarch)
	fmt.Printf("  fips140:  %s\n", fips)
	if vcs != "" {
		fmt.Printf("  revision: %s\n", vcs)
	}
	return nil
}

// ── fingerprint ─────────────────────────────────────────────────────────

// runFingerprint prints the trust-identity fingerprint of a key's public part,
// computed through the same library path the on-box policy uses to match
// anchors — so the value printed on a manifest sheet, read out-of-band, and
// used for the trust decision are provably the one identity.
func runFingerprint(argv []string) error {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	keyPath := fs.String("key", "", "P-384 private key (PKCS#8 PEM)")
	pubPath := fs.String("pub", "", "P-384 public key (SPKI PEM)")
	if err := fs.Parse(argv); err != nil {
		return errUsage
	}
	if (*keyPath == "") == (*pubPath == "") {
		return fmt.Errorf("%w: fingerprint needs exactly one of -key or -pub", errUsage)
	}

	var pub *ecdsa.PublicKey
	if *keyPath != "" {
		priv, err := loadPrivateKey(*keyPath)
		if err != nil {
			return err
		}
		pub = &priv.PublicKey
	} else {
		var err error
		if pub, err = loadPublicKey(*pubPath); err != nil {
			return err
		}
	}
	fp, err := bundle.KeyFingerprint(pub)
	if err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}
	fmt.Println(fp)
	return nil
}

// ── keygen ──────────────────────────────────────────────────────────────

func runKeygen(argv []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	outDir := fs.String("out-dir", ".", "directory to write the keypair into")
	name := fs.String("name", "blakbox-release", "base name for the keypair files")
	if err := fs.Parse(argv); err != nil {
		return errUsage
	}

	keyPath := filepath.Join(*outDir, *name+".key")
	pubPath := filepath.Join(*outDir, *name+".pub")
	fpPath := filepath.Join(*outDir, *name+".fingerprint")

	// Never clobber an existing private key — losing custody of the release
	// key is catastrophic, so make overwrite an explicit manual action.
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("refusing to overwrite existing key %s (move it first)", keyPath)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate P-384 key: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	fp, err := bundle.KeyFingerprint(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("fingerprint: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// Private key mode 0400 — read-only to the owner, matching the old
	// gen_release_key.sh contract.
	if err := os.WriteFile(keyPath, keyPEM, 0o400); err != nil {
		return fmt.Errorf("write %s: %w", keyPath, err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o444); err != nil {
		return fmt.Errorf("write %s: %w", pubPath, err)
	}
	if err := os.WriteFile(fpPath, []byte(fp+"\n"), 0o444); err != nil {
		return fmt.Errorf("write %s: %w", fpPath, err)
	}

	fmt.Printf("generated P-384 release keypair:\n")
	fmt.Printf("  private:     %s   (chmod 0400)\n", keyPath)
	fmt.Printf("  public:      %s\n", pubPath)
	fmt.Printf("  fingerprint: %s\n", fpPath)
	fmt.Printf("\nfingerprint (read this out-of-band to customers):\n  %s\n", fp)
	return nil
}

// ── attest ──────────────────────────────────────────────────────────────

func runAttest(argv []string) error {
	fs := flag.NewFlagSet("attest", flag.ContinueOnError)
	keyPath := fs.String("key", "", "P-384 private key (PKCS#8 PEM) to sign with")
	artifact := fs.String("artifact", "", "file the attestation is about")
	predPath := fs.String("predicate", "", "optional JSON file used as the in-toto predicate")
	predType := fs.String("predicate-type", bundle.BundlePredicateType, "in-toto predicateType")
	subjName := fs.String("subject-name", "", "subject name (default: artifact basename)")
	out := fs.String("out", "", "path to write the DSSE envelope JSON")
	if err := fs.Parse(argv); err != nil {
		return errUsage
	}
	if *keyPath == "" || *artifact == "" || *out == "" {
		return fmt.Errorf("%w: attest needs -key, -artifact and -out", errUsage)
	}

	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}

	dig, err := sha384File(*artifact)
	if err != nil {
		return err
	}

	predicate, err := loadPredicate(*predPath)
	if err != nil {
		return err
	}

	name := *subjName
	if name == "" {
		name = filepath.Base(*artifact)
	}
	subj := bundle.Subject{
		Name:   name,
		Digest: map[string]string{subjectDigestAlg: dig},
	}
	st := bundle.NewStatement(*predType, predicate, subj)

	env, err := bundle.SignStatement(priv, st)
	if err != nil {
		return fmt.Errorf("sign statement: %w", err)
	}
	envJSON, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	if err := os.WriteFile(*out, append(envJSON, '\n'), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *out, err)
	}

	fmt.Printf("signed %s\n", *artifact)
	fmt.Printf("  subject:        %s\n", name)
	fmt.Printf("  %s:         %s\n", subjectDigestAlg, dig)
	fmt.Printf("  predicate-type: %s\n", *predType)
	fmt.Printf("  envelope:       %s\n", *out)
	return nil
}

// ── verify ──────────────────────────────────────────────────────────────

func runVerify(argv []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	var anchors multiFlag
	fs.Var(&anchors, "anchor", "pinned P-384 public key (SPKI PEM); repeatable")
	artifact := fs.String("artifact", "", "file to re-bind the signed digest against")
	in := fs.String("in", "", "DSSE envelope JSON to verify")
	predType := fs.String("predicate-type", bundle.BundlePredicateType,
		"required in-toto predicateType (empty to skip the check)")
	subjName := fs.String("subject-name", "", "optional required subject name")
	if err := fs.Parse(argv); err != nil {
		return errUsage
	}
	if len(anchors) == 0 || *artifact == "" || *in == "" {
		return fmt.Errorf("%w: verify needs at least one -anchor, -artifact and -in", errUsage)
	}

	// Load pinned anchors.
	pubs := make([]*ecdsa.PublicKey, 0, len(anchors))
	for _, a := range anchors {
		pub, err := loadPublicKey(a)
		if err != nil {
			return err
		}
		pubs = append(pubs, pub)
	}

	// Load the envelope.
	envRaw, err := os.ReadFile(*in)
	if err != nil {
		return fmt.Errorf("read envelope %s: %w", *in, err)
	}
	var env dsse.Envelope
	if err := json.Unmarshal(envRaw, &env); err != nil {
		return fmt.Errorf("parse envelope %s: %w", *in, err)
	}

	// (1) Cryptographic verification against the PINNED keys. This checks the
	// DSSE signature, the payloadType, and the in-toto _type, and only accepts
	// signatures made by a key we pinned (never by the envelope's keyid).
	st, err := bundle.VerifyStatement(pubs, &env)
	if err != nil {
		return fmt.Errorf("signature verification FAILED: %w", err)
	}

	// (2) predicateType pin — a statement of a different type signed by the
	// same release key (e.g. a signed export) must not be replayed as an
	// update. Skipped only if the caller explicitly passes -predicate-type "".
	if *predType != "" && st.PredicateType != *predType {
		return fmt.Errorf("predicateType mismatch: envelope is %q, required %q",
			st.PredicateType, *predType)
	}

	// (3) RE-BIND to the actual artifact. The signature above only proves the
	// STATEMENT is authentic; without this step a valid statement could be
	// paired with a different file. Recompute the digest and require a subject
	// to carry exactly that sha384.
	dig, err := sha384File(*artifact)
	if err != nil {
		return err
	}
	matched := matchSubject(st.Subject, dig, *subjName)
	if matched == nil {
		return fmt.Errorf("artifact does NOT match any signed subject digest "+
			"(computed %s %s) — the envelope was not signed over this file", subjectDigestAlg, dig)
	}

	fmt.Printf("VERIFIED\n")
	fmt.Printf("  subject:        %s\n", matched.Name)
	fmt.Printf("  %s:         %s\n", subjectDigestAlg, dig)
	fmt.Printf("  predicate-type: %s\n", st.PredicateType)
	fmt.Printf("  anchors pinned: %d\n", len(pubs))
	return nil
}

// matchSubject returns the subject whose sha384 digest equals dig (and, if
// wantName is non-empty, whose name equals wantName), or nil if none match.
func matchSubject(subjects []bundle.Subject, dig, wantName string) *bundle.Subject {
	for i := range subjects {
		s := subjects[i]
		got, ok := s.Digest[subjectDigestAlg]
		if !ok || got == "" {
			continue
		}
		if got != dig {
			continue
		}
		if wantName != "" && s.Name != wantName {
			continue
		}
		return &subjects[i]
	}
	return nil
}

// ── key + file helpers ──────────────────────────────────────────────────

func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	der, err := pemBytes(path, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse private key %s: %w", path, err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is a %T, not an ECDSA private key", path, key)
	}
	if priv.Curve != elliptic.P384() {
		return nil, fmt.Errorf("%s is not on the P-384 curve", path)
	}
	return priv, nil
}

func loadPublicKey(path string) (*ecdsa.PublicKey, error) {
	der, err := pemBytes(path, "PUBLIC KEY")
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse public key %s: %w", path, err)
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is a %T, not an ECDSA public key", path, key)
	}
	if pub.Curve != elliptic.P384() {
		return nil, fmt.Errorf("%s is not on the P-384 curve", path)
	}
	return pub, nil
}

// pemBytes reads a PEM file and returns the DER of its first block, requiring
// the block type to match want.
func pemBytes(path, want string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block found", path)
	}
	if block.Type != want {
		return nil, fmt.Errorf("%s: expected a %q PEM block, got %q", path, want, block.Type)
	}
	return block.Bytes, nil
}

func loadPredicate(path string) (map[string]any, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read predicate %s: %w", path, err)
	}
	var pred map[string]any
	if err := json.Unmarshal(raw, &pred); err != nil {
		return nil, fmt.Errorf("predicate %s is not a JSON object: %w", path, err)
	}
	return pred, nil
}

// sha384File streams a file through SHA-384 and returns the lowercase hex
// digest. Streaming keeps memory flat regardless of bundle size.
func sha384File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha512.New384()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// multiFlag collects a repeatable string flag (-anchor a -anchor b).
type multiFlag []string

func (m *multiFlag) String() string { return fmt.Sprint([]string(*m)) }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
