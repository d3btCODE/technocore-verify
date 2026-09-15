#!/usr/bin/env python3
"""Vérifie hors ligne une preuve Technocore, sans faire confiance au serveur.

Autonome : ne dépend que de `cryptography`. Aucun accès réseau.

    python verify_proof.py examples/lobby-2026-09-15T18-55-32Z.json

Le point critique est le nonce : c'est `time.time_ns()`, jusqu'à 19 chiffres,
bien au-delà des 53 bits d'un flottant IEEE 754. On le garde en texte exact de
bout en bout (`parse_int=str`), sans quoi la signature échoue en silence.
"""

from __future__ import annotations

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
    """Une preuve qui ne tient pas."""


def base58btc_decode(value: str) -> bytes:
    number = 0
    for character in value:
        digit = BASE58BTC_INDEX.get(character)
        if digit is None:
            raise ProofError(f"caractère base58btc invalide : {character!r}")
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeroes + decoded


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """La clé publique est CONTENUE dans le DID. Aucune requête réseau."""
    prefix = "did:key:"
    if not isinstance(did, str) or not did.startswith(prefix):
        raise ProofError("le DID doit commencer par 'did:key:z6Mk'")
    multibase = did[len(prefix):]
    if len(multibase) != MULTIBASE_LENGTH or not multibase.startswith("z6Mk"):
        raise ProofError("DID non canonique (48 caractères multibase attendus)")
    decoded = base58btc_decode(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(MULTICODEC_ED25519):
        raise ProofError("le DID ne contient pas une clé ed25519-pub")
    try:
        return Ed25519PublicKey.from_public_bytes(decoded[2:])
    except ValueError as error:
        raise ProofError("clé Ed25519 invalide dans le DID") from error


def normalize_message(text: str) -> str:
    """Tout caractère invisible devient une espace, puis strip(). Pas de NFC."""
    if not isinstance(text, str):
        raise ProofError("le texte doit être une chaîne")
    normalized = "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text
    ).strip()
    if not normalized:
        raise ProofError("texte vide après normalisation")
    return normalized


def signed_bytes(room: str, nonce: str, text: str) -> bytes:
    """Les octets réellement signés : room|nonce|text en UTF-8."""
    if NAME_PATTERN.fullmatch(room or "") is None:
        raise ProofError("nom de salle invalide")
    if NONCE_PATTERN.fullmatch(nonce or "") is None:
        raise ProofError("le nonce doit contenir 1 à 19 chiffres ASCII")
    return f"{room}|{nonce}|{normalize_message(text)}".encode("utf-8")


def verify_file(path: Path) -> bool:
    # parse_int=str : le nonce ne devient JAMAIS un nombre.
    doc = json.loads(path.read_text(encoding="utf-8"), parse_int=str, parse_float=str)
    posted = doc.get("posted")
    if not isinstance(posted, dict):
        print(f"FAIL {path.name} : pas d'enregistrement `posted`", file=sys.stderr)
        return False

    room, did = doc.get("room"), posted.get("from")
    nonce, text, sig = posted.get("nonce"), posted.get("text"), posted.get("sig")

    try:
        payload = signed_bytes(room, nonce, text)
        if normalize_message(text) != text:
            raise ProofError("le texte archivé n'est pas la forme normalisée signée")
        if SIGNATURE_PATTERN.fullmatch(sig or "") is None:
            raise ProofError("signature : 86 caractères base64url non padés attendus")
        import base64
        public_key_from_did(did).verify(base64.urlsafe_b64decode(sig + "=="), payload)
    except InvalidSignature:
        print(f"FAIL {path.name} : la signature ne correspond pas au DID", file=sys.stderr)
        return False
    except ProofError as error:
        print(f"FAIL {path.name} : {error}", file=sys.stderr)
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
        print("usage: python verify_proof.py <preuve.json> [...]", file=sys.stderr)
        return 2
    return 0 if all([verify_file(Path(a)) for a in argv]) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
