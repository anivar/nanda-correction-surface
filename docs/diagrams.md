# Diagrams

Architecture and flow diagrams (Mermaid — render inline on GitHub). The protocol
explorer (`explorer/`) renders the same flows interactively, step-by-step, with real
in-process crypto.

## 1. Architecture — three tiers + the correction surface

```mermaid
flowchart LR
  C["Client / Resolver<br/>(verifies every hop, fails closed)"]

  subgraph T1["Tier 1 — Lean Index"]
    IX["Index<br/>signed AgentAddr (Ed25519 / JCS)"]
  end
  subgraph T2["Tier 2 — AgentFacts (W3C VCs)"]
    PH["Provider host (primary)"]
    NH["Neutral host (privacy path)"]
  end
  subgraph ISS["Issuers (did:key)"]
    PV["Provider issuer"]
    AU["Auditor issuer"]
  end
  subgraph T3["Tier 3 — Endpoint"]
    AG["Agent runtime"]
  end

  C -->|"1 · resolve AgentName"| IX
  IX -->|"signed AgentAddr"| C
  C -->|"2 · fetch facts"| PH
  C -->|"2' · privacy path"| NH
  PV -.->|signs VC| PH
  AU -.->|signs VC| PH
  C -->|"3 · act"| AG
```

## 2. Resolution — sequence (including the extension hops)

```mermaid
sequenceDiagram
  autonumber
  participant C as Client
  participant I as Index (Tier 1)
  participant F as Facts host (Tier 2)
  participant A as Agent (Tier 3)
  C->>I: resolve AgentName
  I-->>C: signed AgentAddr (Ed25519 over JCS)
  Note over C: verify signature, pin resolver DID — else fail closed
  C->>F: fetch AgentFacts bundle
  F-->>C: provider VC + auditor VC (+ contestations / severance)
  Note over C: verify VCs (vc-jose-cose), bind subject to agent_did, threshold
  Note over C,F: EXTENSION — exit gate: if severed, refuse
  Note over C,F: EXTENSION — surface affected-party contestations
  C->>A: act on the verified endpoint
  A-->>C: response
```

## 3. The layered model — where the boundary sits

```mermaid
flowchart TB
  subgraph PAPER["NANDA paper — the substrate (CORE)"]
    P1["Tier 1 — lean index"]
    P2["Tier 2 — AgentFacts (W3C VCs)"]
    P3["Tier 3 — endpoint"]
  end
  subgraph EXT["Correction surface — EXTENSION (this work)"]
    E1["Contestation<br/>affected-party signed counter-claim"]
    E2["Self-sovereign exit<br/>severance / key rotation"]
  end
  subgraph CTX["Operator-side authorisation — CONTEXT (cited, not wired)"]
    X1["AuthZEN · AARP · COAZ"]
    X2["Transaction Tokens for Agents"]
  end
  subgraph INST["Institution — out of scope (not a protocol)"]
    N1["authority that can compel correction"]
    N2["remedy"]
  end
  PAPER --> EXT
  CTX -. complements .-> EXT
  EXT --> INST
```

## 4. Self-sovereign exit (severance / key rotation)

```mermaid
sequenceDiagram
  participant V1 as Agent (key v1)
  participant F as Facts host
  participant C as Client
  participant V2 as Successor (key v2)
  V1->>F: severance, signed by v1's own key (successor = v2)
  Note over V1,F: no issuer or registry asked — a did:key has no upstream endpoint
  C->>F: resolve the v1 identity
  F-->>C: AgentFacts + severance
  Note over C: exit gate — severance valid: prior authority is inexecutable
  C--xV1: refuse (fail closed)
  C->>V2: resolve successor — participate on fair terms
```

## 5. Trust direction — operator side vs. the governed party

```mermaid
flowchart LR
  ISS["Issuers / operators"] -->|"attest TO the agent (one-way)"| AG["Agent"]
  AG -->|"acts upon"| AP["Affected party"]
  AP -.->|"signed counter-claim (contestation)"| FACTS["AgentFacts (travels with the agent)"]
  FACTS -.->|"surfaced to"| C["Client → informed refusal"]
```

## 6. Where NANDA sits — the agent-stack ladder

Agent-identity standards answer five questions, bottom to top. The corpus covers
rungs 1–4 — the operator's **control surface** — and stops at rung 5, the governed
party's **correction surface**, by charter. NANDA sits at rung 1 (identity &
discovery); this work's correction surface is a protocol-layer attempt at the empty
rung 5. Steward attributions are verified against primary sources; the explorer
renders this interactively at <https://anivar.github.io/nanda-correction-surface/>.

```mermaid
flowchart BT
  R1["rung 1 · who is acting? — identity &amp; discovery<br/>DID·VC (W3C) · WIMSE·SPIFFE (IETF·CNCF) · WebAuthn (FIDO) · <b>NANDA AgentFacts (MIT)</b>"]:::nanda
  R2["rung 2 · on whose behalf? — delegation<br/>OAuth act/sub, RFC 8693 (IETF) · Identity Chaining (IETF) · AAuth Person Server (IETF)"]
  R3["rung 3 · why? — intent<br/>Agentic JWT (IETF) · AAuth Mission (IETF) · Transaction Tokens (IETF)"]
  R4["rung 4 · may it continue? — continuity<br/>AuthZEN (OpenID) · AAuth missions (IETF) · Txn-Token re-eval (IETF) · CAEP/SSF (OpenID)"]
  R5["rung 5 · who answers when a permitted action is wrong? — consequence / redress<br/><b>no standard</b> · correction surface (THIS WORK) · EU AI Act / PLD (institution)"]:::gap
  R1 --> R2 --> R3 --> R4
  R4 -->|"boundary: surface one (operator control, built) ⟶ surface two (the governed party)"| R5
  classDef gap fill:#3a2c10,stroke:#f5b342,color:#f5e3c0;
  classDef nanda fill:#10243a,stroke:#38bdf8,color:#cfe8fb;
```

Each standard linked to its primary source:

| Rung | Question | Standards (steward) |
|---|---|---|
| **1 · identity** | who is acting? | [DID](https://www.w3.org/TR/did-core/) · [VC](https://www.w3.org/TR/vc-data-model-2.0/) (W3C) · [WIMSE](https://datatracker.ietf.org/wg/wimse/) (IETF) · [SPIFFE](https://spiffe.io/) (CNCF) · [WebAuthn](https://fidoalliance.org/passkeys/) (FIDO) · [NANDA AgentFacts](https://arxiv.org/abs/2507.14263) (MIT) |
| **2 · delegation** | on whose behalf? | [OAuth Token Exchange — RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) · [Identity Chaining](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-chaining/) · [AAuth](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) (IETF) |
| **3 · intent** | why? | [Agentic JWT](https://datatracker.ietf.org/doc/draft-goswami-agentic-jwt/) · AAuth Mission · [Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) (IETF) |
| **4 · continuity** | may it continue? | [AuthZEN](https://openid.net/wg/authzen/) · [CAEP / Shared Signals](https://openid.net/wg/sse/) (OpenID) · AAuth missions · Transaction Tokens re-eval (IETF) |
| **5 · consequence** | who answers when a permitted action is wrong? | — no standards-body spec — · **correction surface (this work)** · [EU AI Act](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai) (institution) |

Riding on rungs 1–4 (not part of the authority ladder): [A2A](https://a2a-protocol.org/)
agent↔agent (LF) · [MCP](https://modelcontextprotocol.io/) tool access (LF/AAIF) ·
[AP2](https://ap2-protocol.org/) payments (LF/Google); security & threats:
[OWASP GenAI](https://genai.owasp.org/), [CoSAI](https://www.coalitionforsecureai.org/)
(OASIS), [NIST](https://www.nist.gov/). NANDA's AgentFacts is a superset of the A2A
Agent Card.
