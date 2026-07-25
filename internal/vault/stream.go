// Package vault implements streaming authenticated encryption for large archives
// using AES-256-GCM, following the well-vetted Tink "AES-GCM-HKDF streaming"
// construction (https://developers.google.com/tink/streaming-aead).
//
// WHY STREAMING (and not one big Seal): AES-GCM must never reuse a nonce under a
// given key, and a single GCM invocation is bounded (~64 GiB, and the 96-bit
// nonce space limits how many messages you can safely encrypt). A whole
// tar.gz can exceed these limits. So we split the plaintext into fixed-size
// SEGMENTS and encrypt each under the SAME key with a UNIQUE, structured nonce.
//
// NONCE / IV structure per segment (12 bytes = 96 bits):
//
//	IV_i = noncePrefix(7) || segmentCounter(4, big-endian) || lastFlag(1)
//
//	- noncePrefix : 7 random bytes, chosen once per file, stored in the header.
//	- segmentCounter: 0,1,2,... ensures every segment gets a distinct nonce.
//	- lastFlag    : 0x01 for the final segment, 0x00 otherwise.
//
// The lastFlag is critical: it authenticates WHERE the stream ends, so an
// attacker cannot silently truncate the archive (drop trailing segments) or
// splice segments between files without detection. The monotonic counter
// likewise prevents reordering or dropping interior segments — any such
// tampering makes a segment's GCM tag fail.
//
// FILE FORMAT:
//
//	magic(8) || version(1) || segmentSize(4, BE) || noncePrefix(7)
//	  || segment_0 || segment_1 || ... || segment_{n-1}
//
// where each segment_i = ciphertext_i || tag_i (GCM appends the 16-byte tag).
// Plaintext segment size is fixed (default 64 KiB); the last may be shorter.
//
// The key is supplied by the caller (derived via the seed pipeline with the
// LabelFileEncryption HKDF label). This package never sees the mnemonic.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	magic        = "SDVLT\x00\x00\x01" // 8 bytes: format identifier
	formatVer    = 1
	noncePrefLen = 7
	counterLen   = 4
	flagLen      = 1
	ivLen        = noncePrefLen + counterLen + flagLen // = 12, the GCM standard nonce size
	tagLen       = 16
	headerLen    = 8 + 1 + 4 + noncePrefLen // magic+version+segSize+noncePrefix

	// DefaultSegmentSize is the PLAINTEXT size of each segment. Ciphertext
	// segments are this plus tagLen. 64 KiB keeps memory tiny and is far under
	// any GCM per-invocation limit.
	DefaultSegmentSize = 64 * 1024

	maxCounter = 0xFFFFFFFF // 2^32-1 segments; at 64 KiB that's 256 TiB. Ample.
)

// Encrypt reads plaintext from src and writes the encrypted stream to dst.
// key must be 32 bytes (AES-256). segmentSize<=0 uses DefaultSegmentSize.
func Encrypt(dst io.Writer, src io.Reader, key []byte, segmentSize int) error {
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	if segmentSize <= 0 {
		segmentSize = DefaultSegmentSize
	}

	aead, err := newGCM(key)
	if err != nil {
		return err
	}

	noncePrefix := make([]byte, noncePrefLen)
	if _, err := rand.Read(noncePrefix); err != nil {
		return fmt.Errorf("generating nonce prefix: %w", err)
	}

	// Write header.
	hdr := make([]byte, 0, headerLen)
	hdr = append(hdr, magic...)
	hdr = append(hdr, formatVer)
	var segSizeBE [4]byte
	binary.BigEndian.PutUint32(segSizeBE[:], uint32(segmentSize))
	hdr = append(hdr, segSizeBE[:]...)
	hdr = append(hdr, noncePrefix...)
	if _, err := dst.Write(hdr); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	buf := make([]byte, segmentSize)
	var counter uint32
	for {
		n, readErr := io.ReadFull(src, buf)
		last := false
		if readErr == io.EOF {
			// Clean end exactly on a segment boundary: emit a final EMPTY segment
			// so the lastFlag is always present and truncation is detectable.
			last = true
			n = 0
		} else if readErr == io.ErrUnexpectedEOF {
			last = true // short final segment
		} else if readErr != nil {
			return fmt.Errorf("reading input: %w", readErr)
		}

		iv := makeIV(noncePrefix, counter, last)
		// Seal appends ciphertext+tag to a nil dst; AAD is nil (nonce structure
		// already binds position and finality).
		ct := aead.Seal(nil, iv, buf[:n], nil)
		if _, err := dst.Write(ct); err != nil {
			return fmt.Errorf("writing segment %d: %w", counter, err)
		}

		if last {
			return nil
		}
		if counter == maxCounter {
			return errors.New("input too large: segment counter exhausted")
		}
		counter++
	}
}

// Decrypt reads the encrypted stream from src and writes recovered plaintext to
// dst. It fails (without emitting the affected data) if any segment's tag is
// invalid, if segments are reordered/dropped, or if the stream is truncated
// (missing final segment).
func Decrypt(dst io.Writer, src io.Reader, key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	hdr := make([]byte, headerLen)
	if _, err := io.ReadFull(src, hdr); err != nil {
		return fmt.Errorf("reading header (not a valid vault file?): %w", err)
	}
	if string(hdr[:8]) != magic {
		return errors.New("bad magic: not a seedvault archive")
	}
	if hdr[8] != formatVer {
		return fmt.Errorf("unsupported format version %d", hdr[8])
	}
	segmentSize := int(binary.BigEndian.Uint32(hdr[9:13]))
	if segmentSize <= 0 || segmentSize > 256*1024*1024 {
		return fmt.Errorf("implausible segment size %d", segmentSize)
	}
	noncePrefix := make([]byte, noncePrefLen)
	copy(noncePrefix, hdr[13:13+noncePrefLen])

	aead, err := newGCM(key)
	if err != nil {
		return err
	}

	// Each ciphertext segment is plaintext segmentSize + tag, except the last.
	ctBuf := make([]byte, segmentSize+tagLen)
	var counter uint32
	for {
		n, readErr := io.ReadFull(src, ctBuf)
		if readErr == io.EOF {
			// No final segment was marked last -> truncated stream.
			return errors.New("truncated archive: missing final segment (possible tampering)")
		}
		last := false
		if readErr == io.ErrUnexpectedEOF {
			last = true // this shorter read is the final segment
		} else if readErr != nil {
			return fmt.Errorf("reading segment %d: %w", counter, readErr)
		} else {
			// We read a full-size ciphertext segment. It MIGHT still be the last
			// segment if the plaintext happened to fill it exactly. We can't know
			// until we try: attempt as non-last first, then as last.
		}

		if last {
			if n < tagLen {
				return fmt.Errorf("segment %d too short", counter)
			}
			iv := makeIV(noncePrefix, counter, true)
			pt, err := aead.Open(nil, iv, ctBuf[:n], nil)
			if err != nil {
				return fmt.Errorf("authentication failed on final segment %d (wrong key or tampering): %w", counter, err)
			}
			if _, err := dst.Write(pt); err != nil {
				return err
			}
			return nil
		}

		// Full-size read: try as a non-last segment.
		ivMid := makeIV(noncePrefix, counter, false)
		pt, errMid := aead.Open(nil, ivMid, ctBuf[:n], nil)
		if errMid == nil {
			if _, err := dst.Write(pt); err != nil {
				return err
			}
			counter++
			continue
		}
		// It didn't open as a middle segment. It may be a final segment that
		// exactly filled the buffer AND is at true EOF. Verify EOF, then retry
		// as last.
		var one [1]byte
		if _, peekErr := src.Read(one[:]); peekErr != io.EOF {
			// There is more data (or a read error): the middle-segment failure
			// was genuine tampering, not an exact-fit final segment.
			return fmt.Errorf("authentication failed on segment %d (wrong key or tampering)", counter)
		}
		ivLast := makeIV(noncePrefix, counter, true)
		pt, errLast := aead.Open(nil, ivLast, ctBuf[:n], nil)
		if errLast != nil {
			return fmt.Errorf("authentication failed on segment %d (wrong key or tampering)", counter)
		}
		if _, err := dst.Write(pt); err != nil {
			return err
		}
		return nil
	}
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	if aead.NonceSize() != ivLen {
		return nil, fmt.Errorf("unexpected GCM nonce size %d", aead.NonceSize())
	}
	return aead, nil
}

func makeIV(noncePrefix []byte, counter uint32, last bool) []byte {
	iv := make([]byte, ivLen)
	copy(iv, noncePrefix)
	binary.BigEndian.PutUint32(iv[noncePrefLen:], counter)
	if last {
		iv[ivLen-1] = 0x01
	}
	return iv
}
