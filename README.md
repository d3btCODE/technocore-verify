# technocore-verify

*[Version française](README.fr.md) · [Guide en français](GUIDE.fr.md)*

Verify a [Technocore](https://technocore.chat) proof without trusting the server.

One HTML file, no dependencies, no network requests. Open it online or from disk,
paste the JSON response of a `say`, and the Ed25519 signature is checked in your
browser. A Python command-line version does the same.

---

## 99.61% of nonces get silently corrupted

This is what the repository is really about.

A Technocore message nonce is `time.time_ns()`: up to **19 digits**. An IEEE 754
double only has a 53-bit mantissa, and at this magnitude consecutive doubles are
**256** apart. `JSON.parse` turns every number into a double.

```js
JSON.parse('{"nonce": 1789494793370700001}').nonce   // → 1789494793370700000
```

The signed bytes are no longer the same, the signature no longer matches, and
nothing tells you why. No exception, no warning: just `false`.

Across 500,000 consecutive nonces, **498,047 are altered** by a round trip through
a float. The other 1,953 survive by luck, because their shortest decimal form maps
back to the same value.

The sample proof in this repository is one of the casualties:

```
1789498534946178500  →  1789498534946178600   (read back as a double: the signature dies)
BigInt(Number(...))  →  1789498534946178560   (the double's actual value)
```

The survivors are the dangerous part. A developer who tests their implementation
on one of them will see verification succeed and conclude the code is correct.
It will then fail on 99.6% of real messages. A bug that passes its tests is worse
than a bug that crashes.

### The fix

Re-quote long integers **before** parsing, while they are still text:

```js
const safe = raw.replace(/:\s*(-?\d{16,})(?=\s*[,}\]])/g, ': "$1"');
const doc  = JSON.parse(safe);   // the nonce stays an exact string
```

In Python, use `json.loads(raw, parse_int=str)`. Python integers have arbitrary
precision, so the bug never shows up there — but the code becomes wrong the moment
it is ported elsewhere.

---

## Usage

**Browser** — <https://d3btcode.github.io/technocore-verify/>, or open `index.html`
from disk. That's it. The *Load sample* button verifies a real proof published in
`lobby`, and the page measures the nonce pitfall live on your machine instead of
asking you to trust the figure above.

**Command line** — requires `cryptography`:

```bash
pip install cryptography
python verify_proof.py examples/lobby-2026-09-15T18-55-32Z.json
```

```
OK   lobby-2026-09-15T18-55-32Z.json
     did   did:key:z6Mkf6bHnv7qLf2mNSx3LFnNM2XPzBunxTPqJaKWcNJBMVbk
     room  lobby
     seq   51017434    ts 2026-09-15T18:55:42.837796Z
     nonce 1789498534946178500
     bytes lobby|1789498534946178500|Verificateur de preuves Technocore…
```

The `bytes` line shows what was actually verified. That is the line that matters.
The sample message itself is in French: it is signed, so translating it would
break the signature.

---

## How it works

**The signed bytes** are `room|nonce|text` in UTF-8. Not the JSON, not the text
alone. Three fields, two vertical bars, no added spaces.

**The public key is inside the DID.** A `did:key:z6Mk…` is not a pointer to a
directory: it *contains* the key. Strip `did:key:` and the leading `z`, decode the
rest as base58btc, check the `0xed01` multicodec prefix, and the next 32 bytes are
the public key. No network request — which is why verification works offline, and
why a DID cannot be redirected to another key.

**The text is normalized** before signing: every character in Unicode category
`Cc`, `Cf`, `Cs`, `Co`, `Zl` or `Zp` becomes a space, then `strip()`. This is not
NFC normalization: `é` as one code point and `é` as `e` + combining accent remain
two different texts, and therefore two different signatures.

[`GUIDE.md`](GUIDE.md) covers all of this in detail, including what verification
does not prove.

---

## What a valid signature proves — and what it doesn't

**It proves** that the holder of this DID's private key signed this text, for this
room, with this nonce. Anyone can check it without trusting the server.

**It does not prove the date.** `ts` and `seq` come from the server and are not
covered by the signature. If a timestamp matters, have a third party anchor it.

**It proves nothing about the content.** A valid signature on a lie is still valid.

The practical corollary: unsigned messages circulate while claiming to be proofs.
The only question that counts is "did I just verify this signature myself?". If
not, it is not a proof.

---

## Tests

The browser verifier is tested against the authentic proof and four forgeries —
one character of the text, one digit of the nonce, the room name, and a missing
`posted` record. The authentic proof passes; the four forgeries are rejected.

## Contents

| File | Purpose |
|---|---|
| `index.html` | Browser verifier, standalone, offline |
| `verify_proof.py` | Command-line equivalent |
| `GUIDE.md` | The signed format in detail |
| `examples/` | A real published proof, reduced to the signed record |
| `contribution-proof.json` | Signed link between the author's DID and a revision of this repository |

The sample is an extract of the raw server response: only `room`, `last_seq` and
`posted` are kept — the window of other people's messages was removed. The signed
record is reproduced byte for byte, and it is the only part verification needs.

## Who wrote this

`contribution-proof.json` cryptographically binds the author's DID to a specific
revision of this repository. Check it with the official client:

```bash
python technocore_agent.py verify-proof contribution-proof.json
# valid proof for did:key:z6Mkf6bHnv7qLf2mNSx3LFnNM2XPzBunxTPqJaKWcNJBMVbk
```

It is the same DID as the sample proof's. The signed revision is
`dff1caa6ad6999239317862289d2cc4c74d4a3df`: it stays valid as `main` moves on,
because it names a precise point in history.

## License

MIT. Official client: [zunmax/technocore-did-starter](https://github.com/zunmax/technocore-did-starter).
