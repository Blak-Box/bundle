package bundle

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"testing"
)

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func encryptToBytes(t *testing.T, pt, cek, aad []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := EncryptStream(&buf, bytes.NewReader(pt), cek, aad); err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return buf.Bytes()
}

func TestStreamRoundTripSizes(t *testing.T) {
	cek, err := GenerateCEK()
	if err != nil {
		t.Fatalf("cek: %v", err)
	}
	aad := []byte("bundle-ctx-42")
	for _, size := range []int{0, 1, 100, SegmentSize - 1, SegmentSize, SegmentSize + 1, 2 * SegmentSize, 2*SegmentSize + 7} {
		pt := randBytes(t, size)
		ct := encryptToBytes(t, pt, cek, aad)
		var out bytes.Buffer
		if err := DecryptStream(&out, bytes.NewReader(ct), cek, aad); err != nil {
			t.Fatalf("size %d: decrypt: %v", size, err)
		}
		if !bytes.Equal(out.Bytes(), pt) {
			t.Fatalf("size %d: round-trip mismatch (got %d bytes)", size, out.Len())
		}
	}
}

func TestStreamRejectsTamper(t *testing.T) {
	cek, _ := GenerateCEK()
	pt := randBytes(t, SegmentSize+500)
	ct := encryptToBytes(t, pt, cek, nil)
	ct[len(ct)/2] ^= 0xff // flip a byte in the ciphertext
	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(ct), cek, nil); err == nil {
		t.Fatal("decrypt accepted tampered ciphertext")
	}
}

func TestStreamRejectsTruncation(t *testing.T) {
	cek, _ := GenerateCEK()
	pt := randBytes(t, 2*SegmentSize)
	ct := encryptToBytes(t, pt, cek, nil)
	truncated := ct[:len(ct)-100] // drop the tail (incl. the last segment)
	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(truncated), cek, nil); err == nil {
		t.Fatal("decrypt accepted a truncated stream")
	}
}

func TestStreamRejectsWrongCEK(t *testing.T) {
	cek1, _ := GenerateCEK()
	cek2, _ := GenerateCEK()
	ct := encryptToBytes(t, randBytes(t, 4096), cek1, nil)
	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(ct), cek2, nil); err == nil {
		t.Fatal("decrypt accepted the wrong CEK")
	}
}

func TestStreamRejectsWrongAAD(t *testing.T) {
	cek, _ := GenerateCEK()
	ct := encryptToBytes(t, randBytes(t, 4096), cek, []byte("aad-A"))
	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(ct), cek, []byte("aad-B")); err == nil {
		t.Fatal("decrypt accepted the wrong stream AAD")
	}
}

func splitFrames(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var frames [][]byte
	for pos := 0; pos < len(b); {
		if pos+5 > len(b) {
			t.Fatal("frame header runs past buffer")
		}
		ctLen := int(binary.BigEndian.Uint32(b[pos+1 : pos+5]))
		end := pos + 5 + ctLen
		if end > len(b) {
			t.Fatal("frame body runs past buffer")
		}
		frames = append(frames, b[pos:end])
		pos = end
	}
	return frames
}

func TestStreamRejectsReorder(t *testing.T) {
	cek, _ := GenerateCEK()
	ct := encryptToBytes(t, randBytes(t, SegmentSize+100), cek, nil)
	frames := splitFrames(t, ct[streamIDSize:])
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	// Swap the two segments, keeping the stream-id preamble.
	var swapped bytes.Buffer
	swapped.Write(ct[:streamIDSize])
	swapped.Write(frames[1])
	swapped.Write(frames[0])
	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(swapped.Bytes()), cek, nil); err == nil {
		t.Fatal("decrypt accepted reordered segments")
	}
}

func TestStreamRejectsOversizedLength(t *testing.T) {
	cek, _ := GenerateCEK()
	// A well-formed stream-id preamble followed by a frame header claiming
	// ~2 GiB. DecryptStream must reject BEFORE allocating (F1).
	var b bytes.Buffer
	b.Write(make([]byte, streamIDSize))
	b.Write([]byte{0, 0x7f, 0xff, 0xff, 0xff}) // flags=0, len=0x7fffffff
	var out bytes.Buffer
	err := DecryptStream(&out, bytes.NewReader(b.Bytes()), cek, nil)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("expected out-of-range rejection, got %v", err)
	}
}

func TestStreamRejectsSplicingAcrossStreams(t *testing.T) {
	cek, _ := GenerateCEK() // SAME cek + SAME (nil) streamAAD for both streams
	a := encryptToBytes(t, randBytes(t, SegmentSize+100), cek, nil)
	bStream := encryptToBytes(t, randBytes(t, SegmentSize+100), cek, nil)
	fa := splitFrames(t, a[streamIDSize:])
	fb := splitFrames(t, bStream[streamIDSize:])
	// Stream A's preamble + A's first segment + B's last segment.
	var spliced bytes.Buffer
	spliced.Write(a[:streamIDSize])
	spliced.Write(fa[0])
	spliced.Write(fb[1])
	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(spliced.Bytes()), cek, nil); err == nil {
		t.Fatal("decrypt accepted a segment spliced from another stream under the same CEK")
	}
}

func TestStreamRejectsExtension(t *testing.T) {
	cek, _ := GenerateCEK()
	ct := encryptToBytes(t, randBytes(t, 100), cek, nil) // one last segment
	extended := append(append([]byte{}, ct...), 0x00, 0x01, 0x02)
	var out bytes.Buffer
	err := DecryptStream(&out, bytes.NewReader(extended), cek, nil)
	if err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("expected trailing-data rejection, got %v", err)
	}
}

func TestStreamRejectsDuplicateSegment(t *testing.T) {
	cek, _ := GenerateCEK()
	ct := encryptToBytes(t, randBytes(t, SegmentSize+100), cek, nil)
	frames := splitFrames(t, ct[streamIDSize:])
	var dup bytes.Buffer
	dup.Write(ct[:streamIDSize])
	dup.Write(frames[0])
	dup.Write(frames[0]) // resend segment 0 in position 1
	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(dup.Bytes()), cek, nil); err == nil {
		t.Fatal("decrypt accepted a duplicated segment")
	}
}

func TestWrapRejectsNonP384Recipient(t *testing.T) {
	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("p256 key: %v", err)
	}
	cek, _ := GenerateCEK()
	if _, err := WrapCEK(p256.PublicKey(), cek); err == nil {
		t.Fatal("wrap accepted a non-P384 recipient")
	}
}

func TestWrapRejectsWrongCEKLength(t *testing.T) {
	recip, _ := ecdh.P384().GenerateKey(rand.Reader)
	if _, err := WrapCEK(recip.PublicKey(), make([]byte, 16)); err == nil {
		t.Fatal("wrap accepted a wrong-length CEK")
	}
}

func TestUnwrapRejectsMalformedEphemeral(t *testing.T) {
	recip, _ := ecdh.P384().GenerateKey(rand.Reader)
	bad := &WrapStanza{EphemeralPublic: []byte("not a valid P-384 point"), Wrapped: make([]byte, 60)}
	if _, err := UnwrapCEK(recip, bad); err == nil {
		t.Fatal("unwrap accepted a malformed ephemeral key")
	}
}

func TestKeywrapRoundTrip(t *testing.T) {
	recip, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("recipient key: %v", err)
	}
	cek, _ := GenerateCEK()
	stanza, err := WrapCEK(recip.PublicKey(), cek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	got, err := UnwrapCEK(recip, stanza)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if !bytes.Equal(got, cek) {
		t.Fatal("unwrapped CEK does not match")
	}
}

func TestKeywrapRejectsWrongRecipient(t *testing.T) {
	a, _ := ecdh.P384().GenerateKey(rand.Reader)
	b, _ := ecdh.P384().GenerateKey(rand.Reader)
	cek, _ := GenerateCEK()
	stanza, err := WrapCEK(a.PublicKey(), cek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if _, err := UnwrapCEK(b, stanza); err == nil {
		t.Fatal("unwrap accepted the wrong recipient key")
	}
}

func TestKeywrapRejectsTamper(t *testing.T) {
	recip, _ := ecdh.P384().GenerateKey(rand.Reader)
	cek, _ := GenerateCEK()
	stanza, err := WrapCEK(recip.PublicKey(), cek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	stanza.Wrapped[len(stanza.Wrapped)-1] ^= 0x01
	if _, err := UnwrapCEK(recip, stanza); err == nil {
		t.Fatal("unwrap accepted a tampered stanza")
	}
}

// TestSealOpenIntegration exercises the full path: generate a CEK, wrap it to a
// recipient, encrypt a payload under it, then unwrap + decrypt on the other side.
func TestSealOpenIntegration(t *testing.T) {
	recip, _ := ecdh.P384().GenerateKey(rand.Reader)
	cek, _ := GenerateCEK()
	stanza, err := WrapCEK(recip.PublicKey(), cek)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	pt := randBytes(t, SegmentSize*2+123)
	aad := []byte("bundle-1234")
	ct := encryptToBytes(t, pt, cek, aad)

	// Receiver side: recover the CEK, then the plaintext.
	recovered, err := UnwrapCEK(recip, stanza)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(ct), recovered, aad); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(out.Bytes(), pt) {
		t.Fatal("end-to-end payload mismatch")
	}
}

// TestSegmentIndexCap enforces the per-key random-nonce invocation bound
// (NIST SP 800-38D): at most 2^32 segments under one stream key. The cap is
// unreachable by streaming (~4 EiB), so the guard is tested directly.
func TestSegmentIndexCap(t *testing.T) {
	if err := segmentIndexOK(maxStreamSegments - 1); err != nil {
		t.Fatalf("last legal segment index rejected: %v", err)
	}
	if err := segmentIndexOK(maxStreamSegments); err == nil {
		t.Fatal("segment index at the nonce bound was accepted")
	}
}
