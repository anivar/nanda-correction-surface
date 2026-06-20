# AgentFacts as a superset of the A2A Agent Card

The paper states AgentFacts "can be viewed as a superset of the Agent Card,
allowing any conforming A2A server to embed its existing card as a skills
extension." `nanda_core/a2a.py` makes that concrete: it projects a **verified**
AgentFacts `credentialSubject` down to a standard
[A2A Agent Card](https://a2a-protocol.org/latest/specification/) (published at
`/.well-known/agent-card.json`).

## Field mapping (down-projection)

| A2A Agent Card field        | AgentFacts source                                  |
|-----------------------------|----------------------------------------------------|
| `name`                      | `label`                                            |
| `description`               | `description`                                      |
| `url`                       | `endpoints.static[0]`                              |
| `version`                   | `version`                                           |
| `provider.organization/url` | `provider.name` / `provider.url`                   |
| `capabilities.streaming`    | `capabilities.streaming`                           |
| `defaultInputModes`/`defaultOutputModes` | `capabilities.modalities`               |
| `skills[]`                  | `skills[]` (id, name [= id], description, input/output modes) |
| `securitySchemes`/`security`| `capabilities.authentication.methods` / `requiredScopes` |

## What NANDA adds on top (the "super" in superset)

These have no A2A Agent Card equivalent — they are exactly the trillion-scale
gaps the paper targets:

- **Cryptographic attestation.** The card's fields are self-declared HTTPS JSON;
  AgentFacts is a W3C Verifiable Credential signed by an issuer, plus an
  independent auditor credential — verifiable regardless of who serves it.
- **Two-step, lean discovery.** A2A is one fetch at the agent's domain; NANDA
  resolves `index → AgentAddr → facts`, so the index stays lean and cacheable.
- **Privacy path.** `private_facts_url` on a neutral host hides the requester
  from the agent's domain. A2A has no equivalent.
- **TTL-scoped routing.** static / rotating / adaptive endpoints with TTLs, vs a
  single `url` assumed stable.
- **Revocation** (stubbed here) and **contestations** (the Level-2 return channel).

The reverse direction is the upgrade story: a plain A2A card can be wrapped as an
AgentFacts credentialSubject and gain all of the above without changing the
agent's runtime.
