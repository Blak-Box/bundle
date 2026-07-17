package bundle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Bulk encryption — the AES-256-GCM STREAM (decision D1).
//
// The payload is split into fixed-size segments, each sealed under a per-stream
// key with a fresh RANDOM 96-bit nonce (via cipher.NewGCMWithRandomNonce, the
// FIPS-safe construction — a counter/deterministic nonce fails GOFIPS140=only).
// Each segment's GCM associated data binds a per-stream random ID, the caller's
// stream AAD, the segment index, and a last-segment flag (never the nonce).
// This authenticates segment ordering, truncation, duplication, extension, and
// cross-stream splicing: the random stream ID means a segment from one stream
// cannot be substituted into another even if both share a CEK.
//
// Wire format:
//
//	[16-byte stream ID], then per segment:
//	[1-byte flags][4-byte big-endian ciphertext length][ciphertext]
//
// flags bit 0 = "last segment". Every stream ends with exactly one last-flagged
// segment (an empty one if the plaintext length is a multiple of the segment
// size), so truncation is always detected. The stream ID preamble is public and
// self-authenticating: every segment's AAD binds it, so tampering with it makes
// every Open fail.
//
// DecryptStream writes each segment's plaintext as it is authenticated, so no
// UNauthenticated plaintext is ever released — but a truncated stream still
// yields an authentic prefix. Treat the output as trustworthy only after
// DecryptStream returns nil.

const (
	// SegmentSize is the plaintext size of each STREAM segment (D1): 1 MiB.
	SegmentSize = 1 << 20
	// CEKSize is the length of a content-encryption key (AES-256).
	CEKSize = 32

	streamKeyInfo = "blakbox/bundle/stream/aes256gcm/v1"

	streamIDSize = 16
	// gcmOverhead is the per-segment expansion of NewGCMWithRandomNonce: a
	// 12-byte prepended random nonce plus a 16-byte GCM tag.
	gcmOverhead = 28
	// maxSegmentCT is the largest legitimate segment ciphertext. Anything
	// larger is forged and is rejected before allocation (F1: no unbounded
	// allocation from an attacker-controlled length).
	maxSegmentCT = SegmentSize + gcmOverhead

	flagLast byte = 1 << 0
)

// GenerateCEK returns a fresh random 256-bit content-encryption key.
func GenerateCEK() ([]byte, error) {
	cek := make([]byte, CEKSize)
	if _, err := rand.Read(cek); err != nil {
		return nil, fmt.Errorf("bundle: generate CEK: %w", err)
	}
	return cek, nil
}

// streamAEAD derives the per-stream AES-256 key from the CEK via HKDF-SHA-384
// (domain-separated) and returns a random-nonce GCM AEAD.
func streamAEAD(cek []byte) (cipher.AEAD, error) {
	if len(cek) != CEKSize {
		return nil, fmt.Errorf("bundle: CEK must be %d bytes, got %d", CEKSize, len(cek))
	}
	key, err := hkdf.Key(sha512.New384, cek, nil, streamKeyInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("bundle: derive stream key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("bundle: aes cipher: %w", err)
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// segAAD binds the stream ID, caller AAD, segment index, and last-flag into a
// segment's GCM associated data (D1) — position, terminality, and stream
// identity are all authenticated; the nonce carries none of it.
func segAAD(streamID, streamAAD []byte, segIdx uint64, isLast bool) []byte {
	aad := make([]byte, 0, len(streamID)+len(streamAAD)+9)
	aad = append(aad, streamID...)
	aad = append(aad, streamAAD...)
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], segIdx)
	aad = append(aad, idx[:]...)
	if isLast {
		aad = append(aad, 1)
	} else {
		aad = append(aad, 0)
	}
	return aad
}

// EncryptStream reads plaintext from r and writes the AES-256-GCM STREAM to w.
func EncryptStream(w io.Writer, r io.Reader, cek, streamAAD []byte) error {
	aead, err := streamAEAD(cek)
	if err != nil {
		return err
	}
	streamID := make([]byte, streamIDSize)
	if _, err := rand.Read(streamID); err != nil {
		return fmt.Errorf("bundle: generate stream id: %w", err)
	}
	if _, err := w.Write(streamID); err != nil {
		return fmt.Errorf("bundle: write stream id: %w", err)
	}
	buf := make([]byte, SegmentSize)
	var segIdx uint64
	for {
		n, rerr := io.ReadFull(r, buf)
		switch rerr {
		case nil:
			if werr := writeSegment(w, aead, streamID, streamAAD, segIdx, false, buf[:n]); werr != nil {
				return werr
			}
			segIdx++
		case io.ErrUnexpectedEOF:
			return writeSegment(w, aead, streamID, streamAAD, segIdx, true, buf[:n])
		case io.EOF:
			return writeSegment(w, aead, streamID, streamAAD, segIdx, true, buf[:0])
		default:
			return fmt.Errorf("bundle: read plaintext: %w", rerr)
		}
	}
}

func writeSegment(w io.Writer, aead cipher.AEAD, streamID, streamAAD []byte, segIdx uint64, isLast bool, pt []byte) error {
	ct := aead.Seal(nil, nil, pt, segAAD(streamID, streamAAD, segIdx, isLast))
	if len(ct) > maxSegmentCT {
		return errors.New("bundle: segment ciphertext too large")
	}
	var hdr [5]byte
	if isLast {
		hdr[0] = flagLast
	}
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(ct)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("bundle: write segment header: %w", err)
	}
	if _, err := w.Write(ct); err != nil {
		return fmt.Errorf("bundle: write segment: %w", err)
	}
	return nil
}

// DecryptStream reverses EncryptStream, writing recovered plaintext to w. It
// rejects any tamper, reorder, duplication, truncation, extension, or
// cross-stream splice.
func DecryptStream(w io.Writer, r io.Reader, cek, streamAAD []byte) error {
	aead, err := streamAEAD(cek)
	if err != nil {
		return err
	}
	streamID := make([]byte, streamIDSize)
	if _, err := io.ReadFull(r, streamID); err != nil {
		return fmt.Errorf("bundle: read stream id: %w", err)
	}
	var segIdx uint64
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.EOF {
				return errors.New("bundle: stream truncated: ended before a last segment")
			}
			return fmt.Errorf("bundle: read segment header: %w", err)
		}
		isLast := hdr[0]&flagLast != 0
		ctLen := binary.BigEndian.Uint32(hdr[1:])
		// F1: reject an out-of-range length BEFORE allocating.
		if ctLen < gcmOverhead || ctLen > maxSegmentCT {
			return fmt.Errorf("bundle: segment %d ciphertext length %d out of range", segIdx, ctLen)
		}
		ct := make([]byte, ctLen)
		if _, err := io.ReadFull(r, ct); err != nil {
			return fmt.Errorf("bundle: read segment %d: %w", segIdx, err)
		}
		pt, err := aead.Open(nil, nil, ct, segAAD(streamID, streamAAD, segIdx, isLast))
		if err != nil {
			return fmt.Errorf("bundle: open segment %d: %w", segIdx, err)
		}
		if _, err := w.Write(pt); err != nil {
			return fmt.Errorf("bundle: write plaintext: %w", err)
		}
		if isLast {
			var extra [1]byte
			if _, err := io.ReadFull(r, extra[:]); err != io.EOF {
				return errors.New("bundle: trailing data after last segment")
			}
			return nil
		}
		segIdx++
	}
}
