"""The AgentFacts -> A2A Agent Card projection (superset claim, made concrete)."""

from nanda_core.a2a import to_agent_card
from nanda_core.models import (
    AgentFactsSubject,
    Authentication,
    Capabilities,
    Endpoints,
    Provider,
    Skill,
)


def test_projection_to_a2a_agent_card():
    subject = AgentFactsSubject(
        id="did:key:z6MkAgent",
        agent_name="urn:agent:acme:translator",
        label="TranslationAssistant",
        description="Low-latency multilingual translation",
        version="1.2.1",
        provider=Provider(name="ACME Corp", url="https://acme.example"),
        endpoints=Endpoints(static=["https://agent.example/invoke"]),
        capabilities=Capabilities(
            modalities=["text", "audio"],
            streaming=True,
            authentication=Authentication(
                methods=["oauth2"], requiredScopes=["translate:real-time"]
            ),
        ),
        skills=[
            Skill(
                id="translation",
                description="Real-time translation",
                inputModes=["text"],
                outputModes=["text"],
            )
        ],
    ).model_dump()

    card = to_agent_card(subject)
    assert card["name"] == "TranslationAssistant"
    assert card["url"] == "https://agent.example/invoke"
    assert card["version"] == "1.2.1"
    assert card["capabilities"]["streaming"] is True
    assert card["defaultInputModes"] == ["text", "audio"]
    assert card["skills"][0]["id"] == "translation"
    assert "oauth2" in card["securitySchemes"]
