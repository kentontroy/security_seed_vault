package keys

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// Fingerprint returns a short, PUBLIC, safe-to-store identifier for a given
// mnemonic+passphrase, derived from the master key via a dedicated verification
// sub-key. Storing it in the clear leaks nothing useful: it is a one-way SHA-256
// over 256-bit-entropy key material, and it is domain-separated from the actual
// volume password (a different HKDF label), so it can't be used to derive the
// password even in principle.
//
// Format: 8 hex chars, grouped as "xxxx-xxxx" for easy visual comparison.
// 32 bits is plenty to catch a mistyped/misspelled word (chance of two different
// mnemonics colliding on the fingerprint is ~1 in 4 billion) while staying short.
func Fingerprint(master []byte) (string, error) {
	vkey, err := SubKey(master, LabelVerification, 32)
	if err != nil {
		return "", err
	}
	defer Zero(vkey)
	sum := sha256.Sum256(vkey)
	h := hex.EncodeToString(sum[:])[:8]
	return h[:4] + "-" + h[4:8], nil
}

// FingerprintEqual compares two fingerprints in constant time and
// case-insensitively (they're hex, so case shouldn't matter, but be lenient).
func FingerprintEqual(a, b string) bool {
	na := strings.ToLower(strings.TrimSpace(a))
	nb := strings.ToLower(strings.TrimSpace(b))
	if len(na) != len(nb) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(na), []byte(nb)) == 1
}
