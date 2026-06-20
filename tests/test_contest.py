"""Tests for the Level-2 contestation primitive: signing and standing."""
from nanda_core import contest
from nanda_core.keystore import Identity


def _setup():
    agent = Identity.generate("agent")
    party = Identity.generate("affected-party")
    receipt, iid = contest.mint_interaction_receipt(agent, "nanda:1", party.did,
                                                    "ordered refund, not honoured")
    c = contest.file_contestation(
        party, agent_id="nanda:1", agent_did=agent.did, interaction_id=iid,
        statement="Agent did not honour the agreed refund within SLA.", receipt=receipt,
    )
    return agent, party, c


def test_valid_contestation_has_standing():
    agent, party, c = _setup()
    v = contest.verify_contestation(c, expected_agent_did=agent.did)
    assert v.valid is True
    assert v.contestant == party.did
    assert "refund" in v.statement


def test_statement_tamper_breaks_contestant_signature():
    agent, _, c = _setup()
    c["statement"] = "Totally different (and unsigned) claim."
    v = contest.verify_contestation(c, expected_agent_did=agent.did)
    assert v.valid is False and "signature" in v.reason


def test_contestation_signed_by_impostor_is_rejected():
    agent, party, c = _setup()
    impostor = Identity.generate("impostor")
    # Impostor re-signs but the named contestant is still the real party.
    from nanda_core import crypto
    body = {k: v for k, v in c.items() if k != "proof"}
    forged = crypto.sign_record(body, impostor.private_key,
                                verification_method=impostor.verification_method)
    v = contest.verify_contestation(forged, expected_agent_did=agent.did)
    assert v.valid is False and "contestant" in v.reason


def test_receipt_for_other_agent_is_rejected():
    agent, _, c = _setup()
    other_agent = Identity.generate("other-agent")
    v = contest.verify_contestation(c, expected_agent_did=other_agent.did)
    assert v.valid is False


def test_no_standing_without_matching_receipt():
    # A contestant with a receipt naming a DIFFERENT counterparty has no standing.
    agent = Identity.generate("agent")
    party = Identity.generate("party")
    other = Identity.generate("other-party")
    receipt, iid = contest.mint_interaction_receipt(agent, "nanda:1", other.did,
                                                    "interaction with someone else")
    c = contest.file_contestation(
        party, agent_id="nanda:1", agent_did=agent.did, interaction_id=iid,
        statement="I wish to contest.", receipt=receipt,
    )
    v = contest.verify_contestation(c, expected_agent_did=agent.did)
    assert v.valid is False and "standing" in v.reason


def test_forged_receipt_not_signed_by_agent():
    agent = Identity.generate("agent")
    party = Identity.generate("party")
    receipt, iid = contest.mint_interaction_receipt(agent, "nanda:1", party.did, "real")
    receipt["summary"] = "tampered"  # break the agent's signature
    c = contest.file_contestation(
        party, agent_id="nanda:1", agent_did=agent.did, interaction_id=iid,
        statement="claim", receipt=receipt,
    )
    v = contest.verify_contestation(c, expected_agent_did=agent.did)
    assert v.valid is False and "receipt" in v.reason


def test_contestation_grafted_onto_other_registry_entry_is_rejected():
    # A contestation valid for nanda:1 must not be accepted when resolving nanda:2,
    # even though both share the same agent did.
    agent = Identity.generate("agent")
    party = Identity.generate("party")
    receipt, iid = contest.mint_interaction_receipt(agent, "nanda:1", party.did, "job")
    c = contest.file_contestation(
        party, agent_id="nanda:1", agent_did=agent.did, interaction_id=iid,
        statement="dispute", receipt=receipt,
    )
    assert contest.verify_contestation(c, expected_agent_did=agent.did,
                                       expected_agent_id="nanda:1").valid is True
    grafted = contest.verify_contestation(c, expected_agent_did=agent.did,
                                          expected_agent_id="nanda:2")
    assert grafted.valid is False
