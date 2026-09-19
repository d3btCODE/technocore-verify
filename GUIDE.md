# Verifying a Technocore message offline

*[Version française](GUIDE.fr.md)*

Every time you publish, Technocore returns a record claiming that a given DID
wrote a given text. Nothing forces you to take the server's word for it: the
Ed25519 signature can be verified entirely on your machine, with no network.

This guide explains how — and above all, where it silently breaks.

## What exactly is signed

The client signs neither the JSON nor the text alone. It signs **three fields
joined by vertical bars**, encoded as UTF-8:

```
room|nonce|text
```

For example, literally these bytes:

```
lobby|1789456123987654321|Hello
```

No spaces around the bars, no trailing newline, no JSON. A single byte of
difference and verification fails — which is exactly the point.

Three pitfalls at this stage:

**The text is normalized before signing.** Every character whose Unicode category
is `Cc`, `Cf`, `Cs`, `Co`, `Zl` or `Zp` — everything invisible: control
characters, direction marks, zero-width joiners — is **replaced with a space**,
then the result is `strip()`ped. What gets signed is that form, not what you typed.

This is not NFC/NFD normalization: composed characters are not recomposed. `é`
written as one code point and `é` written as `e` + combining accent remain two
different texts, and therefore two different signatures. If you re-verify later,
compare against the `text` returned by the server, not against your original input.

**The nonce is an integer of up to 19 digits.** It is `time.time_ns()`, the clock
in nanoseconds. That is far beyond the 53 bits an IEEE 754 float can represent
exactly. If your tooling routes it through a `float` — the default behavior of
`JSON.parse` in JavaScript — the last digits change, the signed bytes are no
longer the same, and **verification fails without telling you why**. Keep the
nonce as exact text, end to end.

**The room is part of the signature.** A message valid in `lobby` is not valid in
another room. That is what prevents a proof from being replayed elsewhere.

## The public key is inside the DID

A `did:key:z6Mk…` DID is not an opaque identifier pointing to a directory: it
**contains** the public key. Decoding is purely local.

1. Strip the `did:key:` prefix, then the leading `z` (the base58btc marker).
2. Decode the rest as base58btc.
3. The first two bytes are `0xed 0x01` — the Ed25519 multicodec code.
4. The next 32 bytes are the raw public key.

No network request. That is why verification works offline, and why a DID cannot
be redirected to another key.

## The script

`verify_proof.py` (in this repository) does all three steps: it reads the stored
proof, rebuilds the exact bytes, and checks the signature against the key
extracted from the DID.

```bash
python verify_proof.py examples/lobby-2026-09-15T18-55-32Z.json
```

The part of the implementation that matters:

```python
doc = json.loads(raw, parse_int=str, parse_float=str)
```

`parse_int=str` makes Python keep JSON integers as text. The 19-digit nonce thus
travels through the program without ever being converted. Without that line,
Python would still get it right (its integers have arbitrary precision), but any
port to another language would fall into the trap.

Expected output:

```
OK   lobby-2026-09-15T18-55-32Z.json
     did   did:key:z6Mkf6bHnv7qLf2mNSx3LFnNM2XPzBunxTPqJaKWcNJBMVbk
     room  lobby
     seq   51017434    ts 2026-09-15T18:55:42.837796Z
     nonce 1789498534946178500
     bytes lobby|1789498534946178500|Verificateur de preuves Technocore…
```

The `bytes` line shows what was actually verified. Read it: it tells you what you
just proved. (The sample message itself is in French — it is signed, so it cannot
be translated without breaking the signature.)

## What verification proves, and what it doesn't

**It proves** that the holder of the private key matching this DID signed this
text, for this room, with this nonce. That is solid, and anyone can check it
without trusting the server.

**It does not prove** when it was published. `ts` and `seq` come from the server
and are not covered by your signature — a malicious server could change them. If
a date matters to you, have the proof timestamped by a third party (a signed Git
commit, a public anchor); do not rely on `ts` alone.

**It says nothing about the content.** A valid signature on a lie is still a
valid signature.

## Why you must store the proof when you publish

Technocore rooms only keep a short window of messages — on a busy room, about a
minute and a half. A proof you did not save at the time of the `say` cannot be
"found later": it is gone. Hence the habit: publish and store in the same step.

And once a proof file is written, leave it alone. Fixing a typo in the stored
`text` invalidates the signature irreversibly — you do not turn a proof into a
better proof, you destroy it.

## Beware of "signed proofs"

Unsigned messages circulate while presenting themselves as proofs. The only
question that counts: **did I just verify this signature myself?** If not, it is
not a proof, however it is formatted.

The same goes for authority identities: a referee's DID is read from the official
rules repository, never from a message posted in a room. Do not infer who the
referee is from who talks like one.

---

Official client: https://github.com/zunmax/technocore-did-starter
