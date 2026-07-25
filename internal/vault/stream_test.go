package vault

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func mustKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestStreamRoundTripSizes(t *testing.T) {
	key := mustKey(t)
	// Use small segment sizes to exercise boundaries, including exact multiples.
	for _, seg := range []int{16, 64} {
		for _, size := range []int{0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 128, 200} {
			plain := make([]byte, size)
			rand.Read(plain)

			var enc bytes.Buffer
			if err := Encrypt(&enc, bytes.NewReader(plain), key, seg); err != nil {
				t.Fatalf("encrypt seg=%d size=%d: %v", seg, size, err)
			}
			var dec bytes.Buffer
			if err := Decrypt(&dec, bytes.NewReader(enc.Bytes()), key); err != nil {
				t.Fatalf("decrypt seg=%d size=%d: %v", seg, size, err)
			}
			if !bytes.Equal(dec.Bytes(), plain) {
				t.Fatalf("round-trip mismatch seg=%d size=%d", seg, size)
			}
		}
	}
}

func TestTamperDetected(t *testing.T) {
	key := mustKey(t)
	plain := make([]byte, 500)
	rand.Read(plain)
	var enc bytes.Buffer
	if err := Encrypt(&enc, bytes.NewReader(plain), key, 64); err != nil {
		t.Fatal(err)
	}
	b := enc.Bytes()
	b[headerLen+5] ^= 0x01 // flip a byte in the first ciphertext segment
	var dec bytes.Buffer
	if err := Decrypt(&dec, bytes.NewReader(b), key); err == nil {
		t.Fatal("expected authentication failure on tampered ciphertext")
	}
}

func TestTruncationDetected(t *testing.T) {
	key := mustKey(t)
	plain := make([]byte, 500)
	rand.Read(plain)
	var enc bytes.Buffer
	if err := Encrypt(&enc, bytes.NewReader(plain), key, 64); err != nil {
		t.Fatal(err)
	}
	// Keep only the header + first full ciphertext segment; drop the rest.
	full := headerLen + (64 + tagLen)
	trunc := enc.Bytes()[:full]
	var dec bytes.Buffer
	if err := Decrypt(&dec, bytes.NewReader(trunc), key); err == nil {
		t.Fatal("expected truncation to be detected")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	key := mustKey(t)
	other := mustKey(t)
	var enc bytes.Buffer
	if err := Encrypt(&enc, bytes.NewReader([]byte("hello world")), key, 64); err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if err := Decrypt(&dec, bytes.NewReader(enc.Bytes()), other); err == nil {
		t.Fatal("expected wrong key to be rejected")
	}
}
