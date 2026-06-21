"""Ed25519 signing/verification and the detached-signature-over-JCS record format.

This is the verification primitive for the *lean index* tier. The paper calls for
the AgentAddr to be a lightweight, cacheable, Ed25519-signed object — small enough
to redistribute without re-querying the index. A detached signature over the
canonical bytes is the right shape for that: the signature lives in a `proof`
field beside the data, the signed payload is exactly the human-readable canonical
JSON (nothing hidden inside an envelope), and verification needs no JOSE parser —
just canonicalise and check.

We deliberately use a *different* mechanism for the richer AgentFacts tier
(full W3C Verifiable Credentials as JWTs — see vc.py). Matching the verification
mechanism to each tier's volatility is a deliberate design judgement.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import canonicalize

PROOF_KEY = "proof"


# --- base64url helpers (no padding, as in JOSE) ---------------------------------


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# --- key generation and (de)serialisation --------------------------------------


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key_to_b64(pub: Ed25519PublicKey) -> str:
    """base64url of the raw 32-byte Ed25519 public key."""
    return b64u_encode(pub.public_bytes_raw())


def public_key_from_b64(s: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(b64u_decode(s))


def private_key_to_b64(priv: Ed25519PrivateKey) -> str:
    """base64url of the raw 32-byte seed. Demo persistence only — never ship this."""
    return b64u_encode(priv.private_bytes_raw())


def private_key_from_b64(s: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(b64u_decode(s))


# --- raw byte signing ----------------------------------------------------------


def sign_bytes(priv: Ed25519PrivateKey, data: bytes) -> bytes:
    return priv.sign(data)  # cryptography always returns a detached 64-byte sig


def verify_bytes(pub: Ed25519PublicKey, sig: bytes, data: bytes) -> bool:
    # Fail closed by contract: return True ONLY for a genuine, valid signature;
    # any other input — wrong type, malformed sig, mismatch — returns False.
    if not isinstance(pub, Ed25519PublicKey):
        return False
    try:
        pub.verify(sig, data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        # InvalidSignature: mismatch or malformed/wrong-length signature.
        # ValueError/TypeError: non-bytes or otherwise unusable inputs.
        # All are verification failures — fail closed, never propagate.
        return False


# --- the signed-record format (detached Ed25519 over JCS) ----------------------


def sign_record(
    record: dict,
    priv: Ed25519PrivateKey,
    *,
    verification_method: str | None = None,
) -> dict:
    """Return `record` with a `proof` field: a detached Ed25519 signature over the
    JCS-canonical bytes of every field *except* `proof` itself.

    `verification_method` (optional) records which key signed — e.g. a did:key
    URL — so a verifier knows what to check against.
    """
    body = {k: v for k, v in record.items() if k != PROOF_KEY}
    sig = sign_bytes(priv, canonicalize(body))
    proof = {"type": "Ed25519Signature2020-detached", "sig": b64u_encode(sig)}
    if verification_method:
        proof["verificationMethod"] = verification_method
    return {**body, PROOF_KEY: proof}


def verify_record(record: dict, pub: Ed25519PublicKey) -> bool:
    """Verify a record produced by sign_record(). Fails closed: any missing/
    malformed proof, or any mutation of a signed field, returns False."""
    proof = record.get(PROOF_KEY)
    if not isinstance(proof, dict) or not isinstance(proof.get("sig"), str):
        return False
    try:
        sig = b64u_decode(proof["sig"])
    except Exception:
        return False
    body = {k: v for k, v in record.items() if k != PROOF_KEY}
    return verify_bytes(pub, sig, canonicalize(body))
