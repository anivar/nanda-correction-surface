"""Tests for the Tier-1 AgentAddr: signing, verification, fail-closed on tamper."""
from nanda_core import crypto
from nanda_core.keystore import Identity
from nanda_core.models import AgentAddr, sign_agentaddr


def _addr() -> AgentAddr:
    return AgentAddr(
        agent_id="nanda:11111111-1111-1111-1111-111111111111",
        agent_name="urn:agent:acme:translator",
        primary_facts_url="http://facts-primary:8000/facts/nanda:1",
        private_facts_url="http://facts-neutral:8000/facts/nanda:1",
        ttl=3600,
    )


def test_agentaddr_signed_and_verified():
    resolver = Identity.generate("index-resolver")
    signed = sign_agentaddr(_addr(), resolver)
    assert signed["proof"]["verificationMethod"] == resolver.verification_method
    assert crypto.verify_record(signed, resolver.private_key.public_key()) is True


def test_agentaddr_field_tamper_detected():
    resolver = Identity.generate("index-resolver")
    signed = sign_agentaddr(_addr(), resolver)
    # Redirect the facts pointer — the classic attack the signature must stop.
    signed["primary_facts_url"] = "http://evil.example/facts"
    assert crypto.verify_record(signed, resolver.private_key.public_key()) is False


def test_agentaddr_resigned_by_attacker_key_is_caught_by_policy():
    # An attacker who re-signs with their own key produces a valid signature for
    # THEIR key, but the verificationMethod no longer matches the trusted resolver.
    resolver = Identity.generate("index-resolver")
    attacker = Identity.generate("attacker")
    signed = sign_agentaddr(_addr(), resolver)
    signed["primary_facts_url"] = "http://evil.example/facts"
    forged = crypto.sign_record(
        {k: v for k, v in signed.items() if k != "proof"},
        attacker.private_key,
        verification_method=attacker.verification_method,
    )
    # Signature is internally valid...
    assert crypto.verify_record(forged, attacker.private_key.public_key()) is True
    # ...but a client pinned to the resolver key rejects it.
    assert crypto.verify_record(forged, resolver.private_key.public_key()) is False
    assert forged["proof"]["verificationMethod"] != resolver.verification_method
