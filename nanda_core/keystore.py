"""Identity helper + simple key persistence for the demo.

An `Identity` bundles an Ed25519 private key with its did:key and verification
method, plus a `sign()` shortcut. Issuers (provider, auditor), agents and
affected parties are all just Identities with different roles.

Persistence here is deliberately minimal — base64 seed files / JSON — because the
brief asks for a prototype, not a key-management product. Secrets live only under
the gitignored `shared/` directory.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import crypto, didkey


@dataclass
class Identity:
    name: str
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, name: str) -> Identity:
        return cls(name=name, private_key=crypto.generate_private_key())

    @property
    def did(self) -> str:
        return didkey.did_from_private(self.private_key)

    @property
    def verification_method(self) -> str:
        return didkey.verification_method(self.did)

    def sign(self, data: bytes) -> bytes:
        return crypto.sign_bytes(self.private_key, data)

    # --- (de)serialisation -----------------------------------------------------

    def to_secret_dict(self) -> dict:
        """Includes the private seed — for demo state under shared/ only."""
        return {
            "name": self.name,
            "did": self.did,
            "private_key": crypto.private_key_to_b64(self.private_key),
        }

    @classmethod
    def from_secret_dict(cls, d: dict) -> Identity:
        return cls(name=d["name"], private_key=crypto.private_key_from_b64(d["private_key"]))

    def to_public_dict(self) -> dict:
        return {"name": self.name, "did": self.did, "verificationMethod": self.verification_method}


def load_or_create_private_key(path: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from `path` (base64 seed), creating and
    persisting a new one if absent. Used by the index for a stable resolver key
    across restarts."""
    if os.path.exists(path):
        with open(path, encoding="ascii") as fh:
            return crypto.private_key_from_b64(fh.read().strip())
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    priv = crypto.generate_private_key()
    with open(path, "w", encoding="ascii") as fh:
        fh.write(crypto.private_key_to_b64(priv))
    return priv


def write_json(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)


def read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)
