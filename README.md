# seedvault

A small, self-contained Go utility that encrypts your sensitive files (W-2s, tax
records, saved messages) into a single **encrypted, compressed archive**, using a
key **deterministically derived from a 12-word BIP-39 mnemonic** plus an optional
passphrase — so you never store an encryption key on disk. Lose the machine, keep
the words: you can always re-derive the same key and decrypt.

**No FUSE, no kernel extensions, no mounting layer** — a folder goes in, one
encrypted file comes out. Works identically on macOS (Intel or Apple Silicon),
Linux, and Windows.

```
your folder
   │  tar (bundle) → gzip (compress)
   ▼
compressed stream
   │  AES-256-GCM streaming AEAD  (chunked; tamper- & truncation-evident)
   ▼
vault.tar.gz.enc              ← the single encrypted archive you back up to USB

  the AES key is derived from your words:
   12-word mnemonic (+ optional passphrase)
      │  BIP-39 (PBKDF2-HMAC-SHA512)  →  Argon2id (t=3, 256 MiB, p=4)
      ▼
   32-byte MASTER KEY            ← never written to disk; only in RAM while running
      │  HKDF-SHA256(info = "…file-encryption:aes-256-gcm:v1")
      ▼
   32-byte AES-256 key
```

> **History / VeraCrypt:** earlier iterations derived a *VeraCrypt volume
> password* instead of encrypting directly. That path was removed because
> VeraCrypt on macOS needs FUSE/kernel extensions; the `encrypt`/`decrypt`
> commands below are the current, kext-free approach.

## Why this shape

- **No key file to steal.** The only long-term secret is the mnemonic, which you
  keep on paper/metal — not on the computer. Malware scanning your disk finds only
  ciphertext.
- **Wallet-style recovery.** The 12 words (optionally + a "25th word" passphrase)
  regenerate the key, on any machine, deterministically.
- **Standard, audited primitives.** BIP-39, Argon2id, HKDF, AES-256-GCM — no
  hand-rolled ciphers. The streaming format follows the well-known Tink
  AES-GCM-HKDF-streaming construction.
- **Portable & simple to back up.** The vault is one file. Copy it to USB, cloud,
  wherever — it's useless without your words.

## How the encryption works (and why streaming)

AES-GCM must never reuse a nonce under one key, and a single GCM call is size-
limited. A whole archive can exceed that, so the archive is split into fixed 64
KiB **segments**, each encrypted under the same key with a unique structured
nonce:

```
IV_i = noncePrefix(7 random bytes) || segmentCounter(4B) || lastFlag(1B)
```

- The **counter** makes every segment's nonce unique and prevents reordering or
  dropping interior segments.
- The **lastFlag** (0x01 only on the final segment) authenticates where the
  stream ends, so an attacker cannot silently **truncate** the archive.

Any tampering, truncation, wrong key, or wrong passphrase makes a segment's GCM
tag fail, and decryption aborts before writing bad data.

## Build

Requires Go 1.22+.

```bash
cd seedvault
go mod tidy      # fetches go-bip39, x/crypto, x/term
go build -o seedvault ./cmd/seedvault
go test ./...    # round-trip, tamper, truncation, wrong-key, key-derivation tests
```

> The crypto pipeline was independently verified, but this was **not** compiled
> in the environment it was authored in. Run `go test ./...` yourself; it should
> pass. Review the code before trusting it with real data.

## Use

### First-time setup (start to finish)

Do this on a trusted, ideally offline machine.

```bash
# 1) Create a fresh 12-word mnemonic. Write the words on PAPER, then clear screen.
./seedvault generate

# 2) Record the verification fingerprint (safe to store; not your key).
./seedvault verify                       # prints e.g. "fingerprint: e656-3249"

# 3) Confirm you wrote the words down correctly BEFORE relying on them.
./seedvault verify --expect e656-3249    # expect MATCH

# 4) Encrypt a folder into a single archive (prompts for mnemonic + passphrase).
./seedvault encrypt ~/Documents/vault ~/vault.tar.gz.enc

# 5) Copy the archive to your USB. The file IS the whole vault.
cp ~/vault.tar.gz.enc /Volumes/MyUSB/
```

### Recovery / decryption, on any machine

```bash
./seedvault decrypt /Volumes/MyUSB/vault.tar.gz.enc ~/restored
#   -> prompts for the same words + passphrase, extracts into ~/restored/
```

### Command reference

```bash
./seedvault generate                     # fresh 12-word mnemonic (do this OFFLINE)
./seedvault verify [--expect XXXX-XXXX]  # show or check the fingerprint
./seedvault encrypt <folder> [out.enc]   # tar+gzip+encrypt a folder
./seedvault decrypt <archive.enc> <dir>  # decrypt+extract an archive
```

### Checking your mnemonic with `verify`

Right after `generate`, record the short **fingerprint** — a safe-to-store,
one-way value that is *not* your key and cannot reveal it:

```bash
./seedvault verify                    # "fingerprint: e656-3249"
./seedvault verify --expect e656-3249 # MATCH / MISMATCH
```

Because the fingerprint depends on the passphrase too, a match confirms **both**
the 12 words and the passphrase. It uses a separate HKDF label from the actual
encryption key, so storing it leaks nothing.

## CRITICAL recovery parameters (write these down with your mnemonic)

Your archive is decryptable **only** if all of these stay the same. They are not
secret, but they are required for recovery:

- Mnemonic word count: **12** (128-bit entropy)
- BIP-39 passphrase: whatever you chose (or none) — **case-sensitive**
- Argon2id: **type=id, time=3, memory=262144 KiB (256 MiB), parallelism=4, len=32**
- Argon2id salt label: `seedvault:argon2id:master-key:v1`
- HKDF: **SHA-256**, salt=none, info=`seedvault:file-encryption:aes-256-gcm:v1`
- Cipher: **AES-256-GCM**, 64 KiB segments, IV = 7-byte prefix + 4-byte counter + 1-byte last-flag

If you ever change the Argon2id cost or any label, **old archives stop
decrypting**. Version the labels (...:v2) and keep the old code if you migrate.

## Security notes / honest limitations

- **Trusted machine only.** While the tool runs, the seed and key exist in RAM; a
  compromised OS can read them. Zeroization here is best-effort (Go's GC may keep
  copies).
- **The mnemonic is everything.** Anyone with the words (and passphrase, if any)
  can decrypt. Back them up physically, in a couple of locations; never store
  them digitally.
- **Fixed Argon2id salt is intentional.** Determinism requires it, and the
  mnemonic already supplies strong entropy, so Argon2id is a memory-hard *stretch*
  here, not a salt for a weak password. Don't reuse this pattern for low-entropy
  human passwords.
- **Keep 2-3 USB copies;** USB sticks fail. The ciphertext is safe on a lost
  stick because the key isn't there — but a lost stick with a *weak or no*
  passphrase is only as safe as your mnemonic's secrecy.
- **No version history.** Re-encrypting overwrites; keep dated copies if you want
  history (e.g. `vault-2025-07.tar.gz.enc`).
- **Whole-archive model.** `encrypt`/`decrypt` work on the entire archive at once
  (streamed, so memory stays flat, but there's no partial/random file access).
  That fits the "back up my documents" use case; it's not a live mounted drive.

## Layout

```
seedvault/
├── go.mod
├── README.md
├── cmd/seedvault/main.go        # CLI: generate | derive | verify | encrypt | decrypt
└── internal/
    ├── keys/
    │   ├── keys.go              # BIP-39 -> Argon2id -> HKDF (the core)
    │   ├── verify.go            # safe-to-store fingerprint
    │   └── keys_test.go         # derivation / fingerprint tests
    └── vault/
        ├── stream.go           # streaming AES-256-GCM AEAD (Tink-style)
        ├── archive.go          # folder -> tar -> gzip -> encrypt, and reverse
        └── stream_test.go      # round-trip / tamper / truncation / wrong-key tests
```
