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
