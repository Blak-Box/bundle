package bundle

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
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
	frames := splitFrames(t, ct)
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	// Swap the two segments and re-serialize.
	var swapped bytes.Buffer
	swapped.Write(frames[1])
	swapped.Write(frames[0])
	var out bytes.Buffer
	if err := DecryptStream(&out, bytes.NewReader(swapped.Bytes()), cek, nil); err == nil {
		t.Fatal("decrypt accepted reordered segments")
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
