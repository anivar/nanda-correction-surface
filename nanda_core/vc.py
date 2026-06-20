"""W3C Verifiable Credentials for AgentFacts, secured as JWTs (vc-jose-cose).

Tier 2 verification. Where AgentAddr uses a lightweight detached signature over
JCS, the richer AgentFacts are issued as full W3C Verifiable Credentials, because
this tier has different needs:

  - **Host independence.** A VC is signed by its *issuer*, not by whoever serves
    it. So AgentFacts verify identically whether fetched from the provider's
    domain or from a neutral third-party host — which is exactly what makes the
    privacy path safe.
  - **Plural issuers.** A provider can self-assert facts while an independent
    auditor attests to evaluations. The client decides which issuers it requires
    (a threshold trust policy), instead of trusting one anointed authority.
  - **Validity and revocation** are first-class.

We secure VCs with **vc-jose-cose**: a JWS whose payload *is* the VC document.
Per VCDM 2.0 the legacy `vc` JWT claim MUST NOT be present — the credential is the
payload directly. Issuer keys are did:key, so verifying needs no network call.

Note on canonicalisation: unlike the AgentAddr path, JWT-VCs need none — the JWS
signs the exact compact serialisation, so there is nothing to re-canonicalise.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Iterable, Optional

import jwt

from .didkey import decode_did_key
from .keystore import Identity

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
AGENTFACTS_CONTEXT = "https://nanda.ai/agentfacts/v1"
JWT_VC_TYP = "vc+jwt"
_ALG = "EdDSA"


class VCError(Exception):
    """Raised on any verification failure. Callers treat this as fail-closed."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(t: dt.datetime) -> str:
    return t.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(s: str) -> dt.datetime:
    # Accept trailing 'Z' across Python versions.
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


def issue_credential(
    *,
    issuer: Identity,
    subject_id: str,
    claims: dict,
    extra_types: Optional[Iterable[str]] = None,
    validity_days: int = 365,
) -> str:
    """Issue a VC as a signed JWT (vc-jose-cose). `claims` becomes the
    credentialSubject (with `id` = subject_id)."""
    now = _now()
    vc = {
        "@context": [VC_CONTEXT_V2, AGENTFACTS_CONTEXT],
        "id": f"urn:uuid:{uuid.uuid4()}",
        "type": ["VerifiableCredential", *(extra_types or [])],
        "issuer": issuer.did,
        "validFrom": iso(now),
        "validUntil": iso(now + dt.timedelta(days=validity_days)),
        # Revocation pointer (stubbed status check — see trust.py). A production
        # build would use a Bitstring Status List; here it is a credential id the
        # client looks up against a revocation set.
        "credentialStatus": {
            "id": f"urn:uuid:{uuid.uuid4()}",
            "type": "NandaRevocationStub",
        },
        "credentialSubject": {"id": subject_id, **claims},
    }
    return jwt.encode(
        vc,
        issuer.private_key,
        algorithm=_ALG,
        headers={"typ": JWT_VC_TYP, "kid": issuer.verification_method},
    )


def verify_credential(
    token: str,
    *,
    trusted_issuers: Optional[set[str]] = None,
    now: Optional[dt.datetime] = None,
) -> dict:
    """Verify a JWT-VC and return the credential dict, or raise VCError.

    Checks, in order and all fail-closed:
      1. a `kid` is present and resolves to an Ed25519 did:key
      2. the issuer is in the trust policy (if one is supplied)
      3. the JWS signature is valid for that issuer key
      4. the header issuer (kid) matches the credential `issuer`
      5. the validity window (validFrom <= now <= validUntil) holds

    Revocation is checked separately by the client, because it is dynamic state
    that lives outside the (immutable, signed) credential.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise VCError(f"malformed JWT header: {exc}") from exc

    # Reject anything that is not typed as a VC JWT, to stop a non-VC JWT signed
    # by the same key (an access token, an A2A message) being replayed as a
    # credential (vc-jose-cose cross-type confusion).
    if header.get("typ") != JWT_VC_TYP:
        raise VCError(f"wrong token type {header.get('typ')!r}, expected {JWT_VC_TYP!r}")

    kid = header.get("kid")
    if not kid:
        raise VCError("credential has no kid (issuer key) in header")

    issuer_did = kid.split("#", 1)[0]
    if trusted_issuers is not None and issuer_did not in trusted_issuers:
        raise VCError(f"issuer not in trust policy: {issuer_did}")

    try:
        issuer_pub = decode_did_key(kid)
    except ValueError as exc:
        raise VCError(f"bad issuer did:key in kid: {exc}") from exc

    try:
        vc = jwt.decode(token, issuer_pub, algorithms=[_ALG])
    except jwt.PyJWTError as exc:
        raise VCError(f"signature verification failed: {exc}") from exc

    if vc.get("issuer") != issuer_did:
        raise VCError("credential `issuer` does not match signing key (kid)")

    now = now or _now()
    vf, vu = vc.get("validFrom"), vc.get("validUntil")
    # Policy: NANDA emphasises short-lived, bounded credentials (and sub-second
    # revocation), so our verifier REQUIRES a validity window and enforces it
    # fail-closed. This is deliberately stricter than VCDM 2.0, which makes
    # validUntil optional (omitting it would mean "no expiry") — we reject that
    # for AgentFacts rather than accept an unbounded credential.
    if not vf:
        raise VCError("credential missing validFrom")
    if not vu:
        raise VCError("credential missing validUntil (unbounded credentials rejected by policy)")
    if now < _parse_iso(vf):
        raise VCError("credential not yet valid (validFrom in the future)")
    if now > _parse_iso(vu):
        raise VCError("credential expired (past validUntil)")

    return vc
