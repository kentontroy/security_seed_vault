// seedvault — deterministic, seed-phrase-based file encryption.
//
// It NEVER stores a key. You supply the 12-word mnemonic (and optional
// passphrase) at run time; the tool re-derives the same encryption key every
// time via BIP-39 -> Argon2id -> HKDF, and uses it to encrypt/decrypt a folder
// as a single compressed, authenticated archive (tar -> gzip -> AES-256-GCM).
//
// Subcommands:
//   generate   Create a fresh 12-word mnemonic (write it on paper, offline).
//   derive     Enter an existing mnemonic (+passphrase) -> print master key hex.
//   verify     Show or check a fingerprint to catch mnemonic/passphrase typos.
//   encrypt    Tar+gzip+encrypt a folder into a single .tar.gz.enc archive.
//   decrypt    Decrypt & extract a .tar.gz.enc archive back into a folder.
//
// SECURITY POSTURE:
//   - Run on an offline / trusted machine. Anything that can read this process's
//     memory or your terminal while unlocked can capture secrets.
//   - The mnemonic is the root of everything. Back it up on paper/metal, never
//     in a file, screenshot, cloud note, or (obviously) shared with anyone.
//

package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"seedvault/internal/keys"
	"seedvault/internal/vault"

	"github.com/tyler-smith/go-bip39"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "generate":
		cmdGenerate()
	case "derive":
		cmdDerive()
	case "verify":
		cmdVerify()
	case "encrypt":
		cmdEncrypt()
	case "decrypt":
		cmdDecrypt()
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`seedvault — deterministic seed-phrase file encryption (no key stored at rest)

USAGE:
  seedvault generate     Generate a fresh 12-word BIP-39 mnemonic
  seedvault derive       Re-derive & print the 32-byte master key (hex)
  seedvault verify       Show or check a fingerprint to catch typos/misspellings
  seedvault encrypt      Tar+gzip+encrypt a folder to a single .tar.gz.enc file
  seedvault decrypt      Decrypt & extract a .tar.gz.enc archive back to a folder

Typical first-time setup:
  1) seedvault generate                 # write the 12 words on paper, offline
  2) seedvault verify                   # record the short fingerprint it prints
  3) seedvault encrypt <folder> <out>   # create the encrypted archive
Recovery later:
  seedvault verify --expect XXXX-XXXX   # confirm you typed the words correctly
  seedvault decrypt <archive> <dir>     # same words+passphrase => your files back
`)
}

// ---- generate ------------------------------------------------------------

func cmdGenerate() {
	// 128 bits of entropy => 12 words.
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		fatal("generating entropy: %v", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		fatal("generating mnemonic: %v", err)
	}
	keys.Zero(entropy)

	fmt.Println("\n============================================================")
	fmt.Println(" YOUR 12-WORD RECOVERY MNEMONIC — write it down, then clear")
	fmt.Println(" the screen. Anyone with these words (and your passphrase,")
	fmt.Println(" if you set one) can open your vault.")
	fmt.Println("============================================================")
	for i, w := range strings.Fields(mnemonic) {
		fmt.Printf("  %2d. %s\n", i+1, w)
	}
	fmt.Println("============================================================")
	fmt.Println("Next: run `seedvault verify` to record your fingerprint, then")
	fmt.Println("`seedvault encrypt <folder> <out>`. Store the Argon2id params too.")
}

// ---- derive (master key) -------------------------------------------------

func cmdDerive() {
	master := deriveOrExit()
	defer keys.Zero(master)
	fmt.Printf("master key (hex): %s\n", hex.EncodeToString(master))
}

// ---- verify --------------------------------------------------------------

// cmdVerify has two modes:
//
//	seedvault verify                     -> prints the fingerprint for the entered
//	                                        mnemonic+passphrase (record this once).
//	seedvault verify --expect XXXX-XXXX  -> prints the fingerprint AND tells you
//	                                        whether it matches the expected one,
//	                                        exiting non-zero on mismatch.
//
// The fingerprint is safe to store in the clear (see keys.Fingerprint). Use the
// --expect mode to confirm you can retype your mnemonic without spelling errors,
// WITHOUT ever displaying the actual encryption key.
func cmdVerify() {
	expected := ""
	args := os.Args[2:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-h", "--help":
			fmt.Print(`seedvault verify — confirm your mnemonic is entered correctly

  seedvault verify
      Print the short fingerprint for the mnemonic+passphrase you enter.
      Do this right after `+"`generate`"+` and record the fingerprint (it's not secret).

  seedvault verify --expect XXXX-XXXX
      Enter your mnemonic+passphrase; the tool prints its fingerprint and
      checks it against XXXX-XXXX. Matches => you typed it correctly.
      Mismatch => a word is misspelled/out of order, or the passphrase differs.

Notes:
  * The fingerprint is a one-way hash, domain-separated from the volume
    password. It cannot be used to derive or reveal the password.
  * A matching fingerprint confirms BOTH the words AND the passphrase match
    what you recorded.
`)
			return
		case "--expect":
			if i+1 >= len(args) {
				fatal("--expect requires a value, e.g. --expect a1b2-c3d4")
			}
			expected = args[i+1]
			i++
		default:
			fatal("unknown flag %q (see: seedvault verify --help)", args[i])
		}
	}

	master := deriveOrExit()
	defer keys.Zero(master)

	fp, err := keys.Fingerprint(master)
	if err != nil {
		fatal("computing fingerprint: %v", err)
	}
	fmt.Fprintf(os.Stderr, "fingerprint: ")
	fmt.Println(fp) // stdout, so it's scriptable

	if expected != "" {
		if keys.FingerprintEqual(fp, expected) {
			fmt.Fprintln(os.Stderr, "MATCH ✓  your mnemonic + passphrase are correct.")
		} else {
			fmt.Fprintf(os.Stderr, "MISMATCH ✗  expected %s but got %s.\n", expected, fp)
			fmt.Fprintln(os.Stderr, "A word may be misspelled/reordered, or the passphrase differs.")
			os.Exit(1)
		}
	}
}

// ---- encrypt / decrypt (folder <-> encrypted archive) --------------------

// fileKey derives the 32-byte AES-256 file-encryption key from the seed.
func fileKey() []byte {
	master := deriveOrExit()
	defer keys.Zero(master)
	k, err := keys.SubKey(master, keys.LabelFileEncryption, 32)
	if err != nil {
		fatal("deriving file key: %v", err)
	}
	return k
}

func cmdEncrypt() {
	args := os.Args[2:]
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Print(`seedvault encrypt <folder> [output.tar.gz.enc]

Tar + gzip + AES-256-GCM encrypt a whole folder into a single file.
Prompts for your mnemonic (+ optional passphrase) to derive the key.
Default output is "<folder>.tar.gz.enc" next to the folder.
`)
		return
	}
	if len(args) < 1 {
		fatal("usage: seedvault encrypt <folder> [output.tar.gz.enc]")
	}
	src := args[0]
	out := src + ".tar.gz.enc"
	if len(args) >= 2 {
		out = args[1]
	}

	key := fileKey()
	defer keys.Zero(key)

	fmt.Fprintf(os.Stderr, "Encrypting %q -> %q ...\n", src, out)
	if err := vault.EncryptFolder(src, out, key); err != nil {
		// Clean up a partial output on failure.
		_ = os.Remove(out)
		fatal("%v", err)
	}
	fmt.Fprintln(os.Stderr, "Done.")
}

func cmdDecrypt() {
	args := os.Args[2:]
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Print(`seedvault decrypt <archive.tar.gz.enc> <destination-folder>

Decrypt and extract an archive created by 'seedvault encrypt'.
Prompts for your mnemonic (+ optional passphrase) to derive the key.
A wrong key/passphrase or any tampering causes authentication to fail
before any bad data is written.
`)
		return
	}
	if len(args) < 2 {
		fatal("usage: seedvault decrypt <archive.tar.gz.enc> <destination-folder>")
	}
	in := args[0]
	dest := args[1]

	key := fileKey()
	defer keys.Zero(key)

	fmt.Fprintf(os.Stderr, "Decrypting %q -> %q ...\n", in, dest)
	if err := vault.DecryptFolder(in, dest, key); err != nil {
		fatal("%v", err)
	}
	fmt.Fprintln(os.Stderr, "Done.")
}

// ---- shared input helpers ------------------------------------------------

func deriveOrExit() []byte {
	mnemonic := readMnemonic()
	passphrase := readPassphrase()

	master, err := keys.DeriveMasterKey(mnemonic, passphrase)
	// best-effort scrub of the inputs
	mnemonic = ""
	passphrase = ""
	_ = mnemonic
	_ = passphrase
	if err != nil {
		fatal("%v", err)
	}
	return master
}

// readMnemonic reads the 12 words. If stdin is a TTY we prompt; otherwise we
// read a single line (useful for testing, but avoid putting secrets in files).
func readMnemonic() string {
	fmt.Fprint(os.Stderr, "Enter your 12-word mnemonic (space-separated): ")
	line := readLine()
	m := strings.Join(strings.Fields(strings.ToLower(line)), " ")
	if !bip39.IsMnemonicValid(m) {
		fatal("that mnemonic is not valid (check spelling/word count/order)")
	}
	return m
}

// readPassphrase reads the optional BIP-39 passphrase WITHOUT echoing.
func readPassphrase() string {
	fmt.Fprint(os.Stderr, "Optional passphrase (press Enter for none): ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fatal("reading passphrase: %v", err)
		}
		return string(b)
	}
	// Non-TTY fallback: read a line (not hidden). Prefer a TTY for real use.
	return strings.TrimRight(readLine(), "\r\n")
}

func readLine() string {
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil && len(line) == 0 {
		fatal("reading input: %v", err)
	}
	return line
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
