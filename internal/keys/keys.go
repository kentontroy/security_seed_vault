// Package keys implements the deterministic key-derivation pipeline:
//
//   12-word BIP-39 mnemonic (+ optional passphrase)
//        │  bip39.NewSeed  (PBKDF2-HMAC-SHA512, per BIP-39 spec)
//        ▼
//   64-byte BIP-39 seed
//        │  Argon2id  (memory-hard stretch; salt is a fixed domain-separation label)
//        ▼
//   32-byte master key            <-- never written to disk; lives only in RAM
//        │  HKDF-SHA256  (one call per labeled purpose)
//        ▼
//   purpose-specific sub-keys  (e.g. "file-encryption:aes-256-gcm:v1")
//
// Design notes / rationale:
//   - The mnemonic is the ONLY secret you back up (paper/metal). No key file at rest.
//   - The optional BIP-39 passphrase ("25th word") is folded in at the bip39.NewSeed
//     step exactly as the BIP-39 standard specifies, so it behaves like any wallet.
//   - Argon2id parameters are recorded as constants below. If you EVER change them,
//     the derived keys change, so treat them as part of your recovery data.
//   - HKDF "info" labels give domain separation: different labels => independent keys
//     from the same master key. Add new labels for new purposes; never reuse one.
package keys

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// ---- Argon2id parameters -------------------------------------------------
//
// These are part of your recovery parameters. Write them down alongside the
// mnemonic (they are NOT secret, but they must match on restore).
//
// Tune Time/Memory up to taste for your hardware; higher = slower = stronger.
// The defaults below aim at a strong interactive derivation (~<1s on modern
// laptops, using 256 MiB). Verify timing on YOUR machine and adjust.
const (
	argonTime    uint32 = 3         // number of passes
	argonMemory  uint32 = 256 * 1024 // KiB => 256 MiB
	argonThreads uint8  = 4
	masterKeyLen uint32 = 32 // 256-bit master key
)

// argonSalt is a FIXED domain-separation label, not a random salt.
//
// Why fixed? Because derivation must be DETERMINISTIC: the same mnemonic must
// always reproduce the same master key on any machine, with nothing stored.
// The real entropy/uniqueness comes from the mnemonic (and optional passphrase),
// which is already high-entropy, so a per-user random salt is unnecessary and
// would have to be stored (defeating the "nothing at rest" goal). We therefore
// use Argon2id purely as a memory-hard STRETCH over an already-strong secret.
var argonSalt = []byte("seedvault:argon2id:master-key:v1")

// SubKey labels. Add new ones for new purposes; keep old ones stable forever.
const (
	// LabelVerification derives a key used ONLY to produce a public, safe-to-store
	// fingerprint for the `verify` command. It is domain-separated from the file
	// encryption key so the stored fingerprint can never be used to recover it.
	LabelVerification = "seedvault:verification:v1"
	// LabelFileEncryption derives the key for the streaming AES-256-GCM file/archive
	// encryption (encrypt/decrypt commands).
	LabelFileEncryption = "seedvault:file-encryption:aes-256-gcm:v1"
)

// DeriveMasterKey runs mnemonic (+passphrase) -> BIP-39 seed -> Argon2id -> masterKey.
// Returns a 32-byte master key. Caller is responsible for zeroizing it after use
// (see Zero).
func DeriveMasterKey(mnemonic, passphrase string) ([]byte, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid BIP-39 mnemonic (word/checksum error)")
	}
	// BIP-39: passphrase is mixed in here exactly per spec ("" if none).
	seed := bip39.NewSeed(mnemonic, passphrase) // 64 bytes

	master := argon2.IDKey(seed, argonSalt, argonTime, argonMemory, argonThreads, masterKeyLen)
	Zero(seed)
	return master, nil
}

// SubKey derives a purpose-specific key of the requested length from the master
// key using HKDF-SHA256 with the given label as the "info" parameter.
func SubKey(master []byte, label string, length int) ([]byte, error) {
	if len(master) == 0 {
		return nil, fmt.Errorf("empty master key")
	}
	// salt=nil is fine here: the master key is already a uniformly-random,
	// high-entropy key, which is exactly HKDF's "strong IKM" case.
	r := hkdf.New(sha256.New, master, nil, []byte(label))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf read: %w", err)
	}
	return out, nil
}

// Zero overwrites a byte slice in place. Best-effort: Go's GC/compiler may still
// leave copies, but this reduces the window a secret sits in reclaimable memory.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
