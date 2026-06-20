"""RFC 8785 JSON Canonicalisation Scheme (JCS).

The single place we turn a JSON object into the exact bytes that get signed.

Why canonicalise at all? A signature must be over *meaning*, not over one
particular serialisation. Key order, insignificant whitespace and number
formatting can all differ between the signer and a verifier (different
languages, libraries, JSON encoders). JCS pins all of that down deterministically
so a verifier reconstructs byte-for-byte the same input the signer signed —
without the signer having to ship the raw bytes alongside the object.

We use `rfc8785` (Trail of Bits' maintained implementation) rather than rolling
our own; canonicalisation has subtle edge cases (UTF-16 key ordering, ECMAScript
number formatting, NaN/Infinity rejection) that are exactly where hand-rolled
versions go wrong.
"""
from __future__ import annotations

import rfc8785


def canonicalize(obj) -> bytes:
    """Return the RFC 8785 canonical UTF-8 bytes of a JSON-serialisable object.

    Raises rfc8785.CanonicalizationError on non-canonicalisable input
    (e.g. NaN, Infinity), which we let propagate — signing such a record
    would be a bug, not something to paper over.
    """
    return rfc8785.dumps(obj)
