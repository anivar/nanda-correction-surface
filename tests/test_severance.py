"""Tests for the self-sovereign severance (exit) primitive."""

from nanda_core import crypto, severance
from nanda_core.keystore import Identity


def test_valid_self_severance():
    agent = Identity.generate("agent")
    sev = severance.sign_severance(
        agent, "nanda:1", successor_did="did:key:zSucc", reason="rotation"
    )
    assert severance.verify_severance(sev, expected_agent_did=agent.did) is True
    assert sev["successor_did"] == "did:key:zSucc"


def test_only_the_retiring_identity_can_sever():
    agent = Identity.generate("agent")
    impostor = Identity.generate("impostor")
    sev = severance.sign_severance(agent, "nanda:1")
    # The severance is for agent.did; checking it against a different identity fails.
    assert severance.verify_severance(sev, expected_agent_did=impostor.did) is False


def test_forged_severance_rejected():
    # Impostor signs a severance that NAMES the agent's identity — rejected, because
    # the signer (proof) is not the identity being retired.
    agent = Identity.generate("agent")
    impostor = Identity.generate("impostor")
    body = {k: v for k, v in severance.sign_severance(agent, "nanda:1").items() if k != "proof"}
    forged = crypto.sign_record(
        body, impostor.private_key, verification_method=impostor.verification_method
    )
    assert severance.verify_severance(forged, expected_agent_did=agent.did) is False


def test_tampered_severance_rejected():
    agent = Identity.generate("agent")
    sev = severance.sign_severance(agent, "nanda:1", reason="x")
    sev["reason"] = "tampered after signing"
    assert severance.verify_severance(sev, expected_agent_did=agent.did) is False


def test_no_severance_is_not_severed():
    agent = Identity.generate("agent")
    assert severance.verify_severance(None, expected_agent_did=agent.did) is False


def test_severance_bound_to_agent_id_cannot_be_replayed():
    # A severance filed for one registry entry must not retire another entry that
    # merely shares the same key. The agent_id binding is what stops the replay.
    agent = Identity.generate("agent")
    sev = severance.sign_severance(agent, "nanda:1")
    assert (
        severance.verify_severance(sev, expected_agent_did=agent.did, expected_agent_id="nanda:1")
        is True
    )
    assert (
        severance.verify_severance(sev, expected_agent_did=agent.did, expected_agent_id="nanda:2")
        is False
    )
