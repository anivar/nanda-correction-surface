"""did:key for Ed25519 — the substrate-neutral identity used throughout.

A did:key encodes a public key directly in the identifier, so it is
*self-certifying*: a verifier recovers the public key from the DID string with
no network call, no registry, no central anchor. The identity **is** the key.

This is a deliberate architectural stance for this prototype: plural issuers,
each independently verifiable, no mandatory central authority. did:key is the
simplest member of the DID family that gives us that. (did:web would add domain
PKI; a production deployment could mix both — see the README.)

Encoding (per the W3C did:key spec and multicodec table):
    did:key:z<base58btc( 0xed 0x01 || <32-byte raw public key> )>
where 0xed01 is the varint multicodec for ed25519-pub and 'z' is the multibase
prefix for base58btc. Real Ed25519 did:keys therefore always start with `z6Mk`.
"""
from __future__ import annotations

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Multicodec prefix for ed25519-pub (0xed), varint-encoded -> two bytes.
ED25519_MULTICODEC = b"\xed\x01"
_DID_KEY_PREFIX = "did:key:"
_MULTIBASE_BASE58BTC = "z"


def encode_did_key(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes_raw()
    multicodec = ED25519_MULTICODEC + raw
    return _DID_KEY_PREFIX + _MULTIBASE_BASE58BTC + base58.b58encode(multicodec).decode("ascii")


def did_from_private(priv: Ed25519PrivateKey) -> str:
    return encode_did_key(priv.public_key())


def decode_did_key(did: str) -> Ed25519PublicKey:
    """Recover the Ed25519 public key from a did:key string. Raises ValueError
    on anything that is not a well-formed Ed25519 did:key."""
    if not did.startswith(_DID_KEY_PREFIX):
        raise ValueError(f"not a did:key: {did!r}")
    multibase = did[len(_DID_KEY_PREFIX):]
    # A verification-method URL may carry a fragment (did:key:z...#z...); drop it.
    multibase = multibase.split("#", 1)[0]
    if not multibase.startswith(_MULTIBASE_BASE58BTC):
        raise ValueError(f"unsupported multibase in {did!r} (expected base58btc 'z')")
    try:
        decoded = base58.b58decode(multibase[1:])
    except Exception as exc:  # noqa: BLE001 - normalise to ValueError for callers
        raise ValueError(f"bad base58btc in {did!r}: {exc}") from exc
    if decoded[:2] != ED25519_MULTICODEC:
        raise ValueError(f"not an ed25519 did:key (bad multicodec) in {did!r}")
    return Ed25519PublicKey.from_public_bytes(decoded[2:])


def verification_method(did: str) -> str:
    """The verification-method id for a did:key is the DID with its own value as
    the fragment: did:key:z6Mk...#z6Mk... — used as the JWT `kid`."""
    value = did[len(_DID_KEY_PREFIX):]
    return f"{did}#{value}"
