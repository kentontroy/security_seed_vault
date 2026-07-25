# seedvault: Encryption Techniques Summary

A brief reference to the cryptographic building blocks used in this project, why
each is present, and how the encrypted archive is streamed in segments.

## The techniques, at a glance

- **BIP-39 (mnemonic → seed)**
  - Turns 128 bits of randomness into a 12-word mnemonic you can write down.
  - Reverses deterministically: the same words (+ optional passphrase) always
    reproduce the same 64-byte seed.
  - Uses PBKDF2-HMAC-SHA512 internally; the optional passphrase (the "25th word")
    is mixed in here, per the BIP-39 standard.
  - Purpose: human-friendly backup and recovery — the words are the only secret
    stored long-term (on paper/metal), never a key file on disk.

- **Argon2id (seed → master key)**
  - A memory-hard key-derivation function; parameters here: time=3, memory=256
    MiB, parallelism=4, output=32 bytes.
  - "Memory-hard" means it deliberately costs lots of RAM to compute, which makes
    brute-force attacks expensive even on specialized hardware (GPUs/ASICs).
  - Used as a **stretch** over the already-high-entropy seed, not as a salt for a
    weak password. The salt is a fixed label because derivation must be
    deterministic (a random salt would have to be stored, defeating the goal).
  - Purpose: harden the seed into a strong 32-byte master key.

- **HKDF-SHA256 (master key → purpose-specific sub-keys)**
  - A key-derivation function that expands one master key into multiple
    independent sub-keys, each tied to a text label ("info").
  - Different labels produce cryptographically independent keys — this is called
    **domain separation**. Example labels in this project:
    - `seedvault:file-encryption:aes-256-gcm:v1` → the AES key for encryption.
    - `seedvault:verification:v1` → the key behind the safe-to-store fingerprint.
  - Purpose: one seed can safely back many distinct uses, and leaking one
    derived value (e.g. the fingerprint) reveals nothing about the others.

- **AES-256-GCM (the actual file encryption)**
  - A symmetric AEAD cipher: **A**uthenticated **E**ncryption with **A**ssociated
    **D**ata. It provides both confidentiality (data is unreadable without the
    key) and integrity (any tampering is detected).
  - Each encryption produces ciphertext plus a 16-byte **authentication tag**; if
    even one bit of the ciphertext is altered, tag verification fails and
    decryption aborts.
  - Purpose: encrypt the compressed archive, with built-in tamper detection.

- **tar + gzip (bundling and compression, before encryption)**
  - `tar` bundles a whole folder (files, structure, permissions) into one stream.
  - `gzip` compresses that stream.
  - Compression happens **before** encryption because encrypted data looks random
    and won't compress — so you must compress first, then encrypt the result.

## What is a nonce?

- **Nonce** = "**n**umber used **once**." It is a value fed into the cipher
  alongside the key so that encrypting the same data twice produces different
  ciphertext.
- It does **not** need to be secret — it is stored in the file — but it must be
  **unique** for every encryption performed under the same key.
- The danger is **reuse**: encrypting two different chunks with the same
  key *and* the same nonce breaks AES-GCM's security badly (it can leak the
  plaintext relationship and even the authentication key). So nonce uniqueness is
  the single most important rule when using GCM.
- In AES-GCM the nonce is 96 bits (12 bytes). This project builds each nonce with
  a fixed structure (see below) so uniqueness is guaranteed by construction.

## How the gzipped tar is split via streaming

A single AES-GCM operation has hard limits (a 96-bit nonce and a per-message size
bound of roughly 64 GiB), and a whole `tar.gz` can exceed what is safe to encrypt
in one shot. The solution is **streaming encryption**: split the compressed stream
into fixed-size segments and encrypt each one separately, all under the same key
but with a unique, structured nonce per segment. The construction follows the
well-known Tink "AES-GCM-HKDF streaming" design.

- **Segmenting**: the gzip stream is read in fixed **64 KiB** plaintext segments
  (the last segment may be shorter). Everything is streamed through a pipe, so
  memory stays flat no matter how large the archive is.

- **Per-segment nonce (12 bytes)**, built as:

  ```
  nonce = noncePrefix(7 random bytes) || segmentCounter(4 bytes) || lastFlag(1 byte)
  ```

  - **noncePrefix**: 7 random bytes chosen once per file and stored in the header.
  - **segmentCounter**: 0, 1, 2, … — makes every segment's nonce unique and
    prevents segments being **reordered** or **dropped** (a wrong counter → the
    tag fails).
  - **lastFlag**: `0x01` on the final segment only, `0x00` otherwise. This
    authenticates *where the stream ends*, so an attacker cannot silently
    **truncate** the archive by chopping off trailing segments.

- **File format** written to disk:

  ```
  magic(8) || version(1) || segmentSize(4) || noncePrefix(7)
    || segment_0 || segment_1 || ... || segment_n
  ```

  where each `segment_i` is its ciphertext plus a 16-byte GCM tag.

- **On decryption**: each segment is verified and decrypted in order. Any of the
  following causes decryption to fail before writing bad data:
  - a modified byte anywhere (tag mismatch),
  - reordered or dropped segments (counter mismatch),
  - a truncated archive (missing the segment marked with the last-flag),
  - the wrong key or wrong passphrase.

## The pipeline end to end

```
12-word mnemonic (+ optional passphrase)
   │  BIP-39 (PBKDF2-HMAC-SHA512)
   ▼
64-byte seed
   │  Argon2id (memory-hard: t=3, 256 MiB, p=4)
   ▼
32-byte master key            (never stored; only in RAM while running)
   │  HKDF-SHA256(info = "seedvault:file-encryption:aes-256-gcm:v1")
   ▼
32-byte AES-256 key
   │
   ▼
folder → tar → gzip → split into 64 KiB segments → AES-256-GCM per segment
   ▼
vault.tar.gz.enc
```
