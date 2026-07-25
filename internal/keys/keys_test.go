package keys

import (
	"bytes"
	"testing"
)

// A fixed, well-known BIP-39 test mnemonic (12 words). Do NOT use for real vaults.
const testMnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow"

func TestDeriveIsDeterministic(t *testing.T) {
	a, err := DeriveMasterKey(testMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveMasterKey(testMnemonic, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same mnemonic produced different master keys — determinism broken")
	}
	if len(a) != 32 {
		t.Fatalf("expected 32-byte master key, got %d", len(a))
	}
}

func TestPassphraseChangesKey(t *testing.T) {
	none, _ := DeriveMasterKey(testMnemonic, "")
	with, _ := DeriveMasterKey(testMnemonic, "correct horse")
	if bytes.Equal(none, with) {
		t.Fatal("passphrase had no effect on derived key")
	}
}

func TestSubKeyDomainSeparation(t *testing.T) {
	m, _ := DeriveMasterKey(testMnemonic, "")
	k1, _ := SubKey(m, "label-A", 32)
	k2, _ := SubKey(m, "label-B", 32)
	if bytes.Equal(k1, k2) {
		t.Fatal("different labels produced identical sub-keys — domain separation broken")
	}
	// same label must be stable
	k1b, _ := SubKey(m, "label-A", 32)
	if !bytes.Equal(k1, k1b) {
		t.Fatal("same label produced different sub-keys — non-deterministic HKDF")
	}
}

func TestInvalidMnemonicRejected(t *testing.T) {
	if _, err := DeriveMasterKey("not a real mnemonic at all", ""); err == nil {
		t.Fatal("expected invalid mnemonic to be rejected")
	}
}

func TestFingerprintStableAndFormatted(t *testing.T) {
	m1, _ := DeriveMasterKey(testMnemonic, "")
	m2, _ := DeriveMasterKey(testMnemonic, "")
	f1, err := Fingerprint(m1)
	if err != nil {
		t.Fatal(err)
	}
	f2, _ := Fingerprint(m2)
	if f1 != f2 {
		t.Fatal("fingerprint not stable for same mnemonic")
	}
	if len(f1) != 9 || f1[4] != '-' { // "xxxx-xxxx"
		t.Fatalf("unexpected fingerprint format: %q", f1)
	}
}

func TestFingerprintChangesWithPassphrase(t *testing.T) {
	a, _ := DeriveMasterKey(testMnemonic, "")
	b, _ := DeriveMasterKey(testMnemonic, "extra")
	fa, _ := Fingerprint(a)
	fb, _ := Fingerprint(b)
	if fa == fb {
		t.Fatal("fingerprint should differ when passphrase differs")
	}
}

func TestFingerprintEqual(t *testing.T) {
	if !FingerprintEqual("A1B2-c3d4", "a1b2-c3d4") {
		t.Fatal("expected case-insensitive match")
	}
	if FingerprintEqual("a1b2-c3d4", "a1b2-c3d5") {
		t.Fatal("expected mismatch")
	}
}

func TestFingerprintKeyIndependentOfFileKey(t *testing.T) {
	// Ensure the verification key and the file-encryption key are independent,
	// so the stored fingerprint can't reveal the encryption key.
	m, _ := DeriveMasterKey(testMnemonic, "")
	fkey, _ := SubKey(m, LabelFileEncryption, 32)
	vkey, _ := SubKey(m, LabelVerification, 32)
	if bytes.Equal(fkey, vkey) {
		t.Fatal("verification key must differ from file-encryption key")
	}
}
