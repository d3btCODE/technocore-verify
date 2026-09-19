#!/usr/bin/env python3
"""Verify a Technocore proof offline, without trusting the server.

Standalone: depends only on `cryptography`. No network access.

    python verify_proof.py examples/lobby-2026-09-15T18-55-32Z.json

The critical part is the nonce: it is `time.time_ns()`, up to 19 digits, far
beyond the 53 bits of an IEEE 754 float. It is kept as exact text end to end
(`parse_int=str`); otherwise the signature fails silently.
"""

from __future__ import annotations

import base64
import json
import re
import sys
import unicodedata
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

BASE58BTC_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58BTC_INDEX = {c: i for i, c in enumerate(BASE58BTC_ALPHABET)}
MULTICODEC_ED25519 = b"\xed\x01"
MULTIBASE_LENGTH = 48
INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Zl", "Zp"})
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")
NONCE_PATTERN = re.compile(r"[0-9]{1,19}")
SIGNATURE_PATTERN = re.compile(r"[A-Za-z0-9_-]{86}")


class ProofError(Exception):
    """A proof that does not hold."""


def base58btc_decode(value: str) -> bytes:
    number = 0
    for character in value:
        digit = BASE58BTC_INDEX.get(character)
        if digit is None:
            raise ProofError(f"invalid base58btc character: {character!r}")
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeroes + decoded


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """The public key is CONTAINED in the DID. No network request."""
    prefix = "did:key:"
    if not isinstance(did, str) or not did.startswith(prefix):
        raise ProofError("the DID must start with 'did:key:z6Mk'")
    multibase = did[len(prefix):]
    if len(multibase) != MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
        raise ProofError("non-canonical DID (48 multibase characters expected)")
    decoded = base58btc_decode(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise ProofError("the DID does not contain an ed25519-pub key")
    try:
        return Ed25519PublicKey.from_public_bytes(decoded[2:])
    except ValueError as error:
        raise ProofError("invalid Ed25519 key in the DID") from error


def normalize_message(text: str) -> str:
    """Every invisible character becomes a space, then strip(). Not NFC."""
    if not isinstance(text, str):
        raise ProofError("the text must be a string")
    normalized = "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text
    ).strip()
    if not normalized:
        raise ProofError("text is empty after normalization")
    return normalized


def signed_bytes(room: str, nonce: str, text: str) -> bytes:
    """The bytes actually signed: room|nonce|text in UTF-8."""
    if NAME_PATTERN.fullmatch(room or "") is None:
        raise ProofError("invalid room name")
    if NONCE_PATTERN.fullmatch(nonce or "") is None:
        raise ProofError("the nonce must be 1 to 19 ASCII digits")
    return f"{room}|{nonce}|{normalize_message(text)}".encode("utf-8")


def verify_file(path: Path) -> bool:
    # parse_int=str: the nonce NEVER becomes a number.
    doc = json.loads(path.read_text(encoding="utf-8"), parse_int=str, parse_float=str)
    posted = doc.get("posted")
    if not isinstance(posted, dict):
        print(f"FAIL {path.name}: no `posted` record", file=sys.stderr)
        return False

    room, did = doc.get("room"), posted.get("from")
    nonce, text, sig = posted.get("nonce"), posted.get("text"), posted.get("sig")

    try:
        payload = signed_bytes(room, nonce, text)
        if normalize_message(text) != text:
            raise ProofError("the stored text is not the normalized form that was signed")
        if SIGNATURE_PATTERN.fullmatch(sig or "") is None:
            raise ProofError("signature: 86 unpadded base64url characters expected")
        public_key_from_did(did).verify(base64.urlsafe_b64decode(sig + "=="), payload)
    except InvalidSignature:
        print(f"FAIL {path.name}: the signature does not match the DID", file=sys.stderr)
        return False
    except ProofError as error:
        print(f"FAIL {path.name}: {error}", file=sys.stderr)
        return False

    print(f"OK   {path.name}")
    print(f"     did   {did}")
    print(f"     room  {room}")
    print(f"     seq   {posted.get('seq')}    ts {posted.get('ts')}")
    print(f"     nonce {nonce}")
    print(f"     bytes {room}|{nonce}|{text}")
    return True


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: python verify_proof.py <proof.json> [...]", file=sys.stderr)
        return 2
    return 0 if all([verify_file(Path(a)) for a in argv]) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
