# `generate` vs `derive` in seedvault

Two of the seedvault subcommands, `generate` and `derive`, are easy to confuse
but perform genuinely different operations. This note explains the difference and
when you'd use each.

## Short version

- **`generate`** *creates* brand-new secret material (a fresh mnemonic).
- **`derive`** *consumes* an existing mnemonic to reproduce a key from it.

The flow of secret material runs in opposite directions:

```
generate:  (OS randomness)  ─────────────►  mnemonic           [creates words]
derive:    mnemonic         ─────────────►  master key (hex)   [consumes words]
```

## `generate`

Creates new secret material.

- Calls `bip39.NewEntropy(128)` to pull 128 bits of fresh randomness from the OS.
- Converts that entropy into a new 12-word BIP-39 mnemonic.
- Prints the words for you to write down (on paper/metal, offline).

It takes **no input**, and every run produces a **different** mnemonic. This is
the "start a new vault" command — run it once, at the very beginning.

## `derive`

Reproduces a key from an existing mnemonic.

- Prompts you to type your 12 words (plus optional passphrase).
- Runs them through the derivation pipeline: BIP-39 → Argon2id → HKDF.
- Prints the resulting 32-byte **master key** as hex.

It takes your mnemonic **as input** and is fully **deterministic**: the same
words (and passphrase) always yield the same key.

## Important: what `derive` actually prints

`derive` prints the **master key**, not the file-encryption key, and not
anything you feed to `encrypt` / `decrypt`.

The master key is the intermediate value that sits *before* the final HKDF step.
The `encrypt` / `decrypt` commands derive their own file-encryption sub-key from
that master key internally, using the `LabelFileEncryption` HKDF label. So
`derive` is essentially a **diagnostic / inspection tool**:

- It lets you confirm the derivation is deterministic (same words → same key).
- It lets you extract the master key if you're building something else on top of
  seedvault.

## When you actually use each

In normal use — encrypting and decrypting your documents — **you never need
`derive` at all**. The everyday flow is:

1. `generate` — once, to create your mnemonic.
2. `verify` — to confirm you wrote the words down correctly.
3. `encrypt` / `decrypt` — from then on, for your files.

## A note on keeping vs. removing `derive`

Because `derive` prints raw key material to the terminal and isn't part of the
actual encrypt/decrypt workflow, it's reasonable to consider removing it (the
same way the legacy `password` command was removed). Printing a master key to a
terminal is a mild footgun.

Keep it only if you want the master key for inspection or for feeding another
tool. If neither applies, cutting it leaves a leaner, harder-to-misuse utility.
