# What is Argon2id? (in plain English)

Argon2id is a way of turning a password (or, in this project's case, the
seed-derived value) into an encryption key **slowly and expensively on purpose**.

## Why "slow and expensive" is the point

That "on purpose" is the whole point. A normal hash is fast — which is great for
computers but bad for security, because an attacker guessing millions of
passwords per second benefits from speed just as much as you do.

Argon2id deliberately makes each attempt cost real time *and* a large chunk of
memory. So while it adds only a fraction of a second when *you* unlock your
vault, it makes mass guessing enormously expensive for an attacker trying
billions of possibilities.

## The "memory-hard" part

This is what sets Argon2id apart from older methods. Argon2id forces each
computation to fill a big block of RAM (256 MB in this project's setup).

Attackers like to speed up guessing with specialized hardware — GPUs or custom
chips — that can run thousands of guesses in parallel. But that trick relies on
each guess being cheap. When every guess demands hundreds of megabytes of
memory, you can't fit thousands of them side by side, so that hardware advantage
largely collapses. That's the defense you're paying for.

## What the "id" means

The "id" is just the variant name — it's a blend of two internal modes (Argon2i
and Argon2d) that together resist the widest range of attacks. It won a public
competition to become the recommended standard, which is why it's the modern
default choice for this kind of job.

## In one line

**Argon2id is a deliberately slow, memory-hungry key-derivation function that
makes brute-force guessing painfully expensive, while costing you only a moment
when you legitimately unlock your data.**
