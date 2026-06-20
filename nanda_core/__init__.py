"""nanda_core — shared primitives for the NANDA Index prototype.

One source of truth for canonicalisation, signing, did:key and the data models,
imported by every service and by the client. No cryptographic primitive is
implemented here: we wire together PyCA `cryptography` (Ed25519), `rfc8785`
(RFC 8785 JCS) and `PyJWT` (vc-jose-cose).
"""
