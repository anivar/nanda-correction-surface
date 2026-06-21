# NANDA Index — a working prototype

A runnable prototype of the core resolution flow from
*Beyond DNS: Unlocking the Internet of AI Agents via the NANDA Index and Verified
AgentFacts* (Raskar et al., [arXiv:2507.14263](https://arxiv.org/pdf/2507.14263),
v0.3) — plus one focused extension: a **contestation record**, the affected-party
half of the trust object the paper leaves out.

A client resolves an agent by name, walks `index → AgentAddr → AgentFacts →
endpoint`, **verifies and prints every hop**, **fails closed** on any tampering or
forgery, and finally acts on the verified endpoint. Two agents are registered and
resolved (one via the provider path, one via the privacy path).

## Quick start

**With Docker** (brings up the index, two facts hosts, and an agent runtime):

```bash
docker compose up --build -d
docker compose --profile demo run --rm demo
```

**Without Docker** — needs [uv](https://docs.astral.sh/uv/) (it provisions Python
3.14 and the locked deps for you):

```bash
./demo/run_local.sh          # or:  make demo
```

Either way you get the same eight-step walkthrough: register → resolve → tamper →
spoof → contest → exit → registrations → revoke.

Toolchain: **uv** (env + Python 3.14, `uv.lock` pinned), **ruff** (lint + format),
`pytest`. No global Python or `pip` needed.

## What you'll see

| Step | Demonstrates |
|---|---|
| **register** | two agents registered: index entry + AgentFacts issued as W3C VCs (provider + independent auditor), hosted on both a provider host and a neutral host |
| **resolve** | full path for each agent, **every hop verified and printed**; one via the provider (primary) path, one via the **privacy** (neutral-host) path; client then **acts** on the verified endpoint |
| **tamper** | a mutated AgentAddr (redirected facts pointer, inflated ttl, corrupted signature) is **rejected** — fail closed |
| **spoof** | a credential from an **untrusted issuer**, and a **tampered** credential from a trusted issuer, are both **rejected** |
| **contest** | an affected party files a **signed counter-claim** bound to a prior interaction; the client verifies its standing and **surfaces it alongside** the issuers' claims |
| **exit** | self-sovereign severance — the agent retires its own did:key; prior authority becomes **inexecutable** |
| **registrations** | quilt of registration types in action: native, enterprise, and did:key paths |
| **revoke** | issuer-signed revocation entry served by the index and **verified client-side** — only a credential's own trusted issuer may revoke it |

## Architecture

Three NANDA tiers, split by how fast each layer changes, mapped onto services:

```
  client  ──1── index (Tier 1)            GET /resolve  → signed AgentAddr
            │     └─ Ed25519 / JCS, resolver-signed, cacheable pointer record
            │
            ├──2── facts host (Tier 2)     GET /facts/{id} → AgentFacts bundle
            │     ├─ facts-primary  (provider domain)      → primary_facts_url
            │     └─ facts-neutral  (neutral host, privacy)→ private_facts_url
            │        AgentFacts = W3C VCs (provider issuer + auditor issuer)
            │
            └──3── agent runtime (Tier 3)  POST /agents/{slug}/invoke → result

  Resolution walk the client verifies hop-by-hop:
      AgentName → Index → AgentAddr → AgentFacts(VCs) → [contestations] → endpoint
```

- **Tier 1 — lean index.** Returns a small, cacheable `AgentAddr`: identity +
  facts pointers + ttl, signed with **Ed25519 over RFC 8785 JCS** by the index
  resolver. It holds pointers, never metadata.
- **Tier 2 — AgentFacts.** Rich, updatable metadata issued as **W3C Verifiable
  Credentials (JWT / vc-jose-cose)**: a provider self-claim plus an independent
  auditor attestation. Signed by issuers (`did:key`), so they verify regardless
  of which host serves them.
- **Tier 3 — endpoint.** The live agent the client finally calls.

## Verification approach — and why (the design judgement)

The mechanism follows the volatility of each tier:

- **AgentAddr → detached Ed25519 over JCS.** Tiny, cacheable, no envelope, no
  JOSE parser to verify; the signed bytes are exactly the canonical JSON. The
  client **pins the resolver DID**, so a valid-but-wrong-signer record is still
  rejected.
- **AgentFacts → W3C Verifiable Credentials.** Host-independent (this is what
  makes the privacy path safe), multi-issuer with a client-side **threshold**
  (provider required, auditor corroborates), and carries validity + revocation.

The full reasoning, the contestation argument, the standards context (OpenID
AuthZEN, AARP, COAZ), and honest limitations are in
**[docs/design-note.md](docs/design-note.md)**.

## The correction surface (contestation + exit)

The core resolution flow was built and verified end-to-end first. On top of it: AgentFacts is a
one-way object (issuers attest *to* the agent). The contestation record is the
return path — a signed counter-claim from a party the agent acted upon, bound to
an interaction the agent itself acknowledged (the standing anchor), surfaced to
clients next to the issuers' claims. It is the first primitive in the stack
controlled by the *governed* party, not an operator or issuer. See the design note.

## Project layout

```
nanda_core/   canonical (JCS), crypto (Ed25519), did:key, VC (JWT-VC),
              trust policy, contestation, A2A projection, models
index/        Tier 1 — lean index service (signs & serves AgentAddr)
facts/        Tier 2 — AgentFacts host (same code runs as primary and neutral)
agent/        Tier 3 — minimal agent runtime (so "act" is a real round-trip)
issuer/       build & issue provider + auditor VCs
client/       the verifying resolver (prints & verifies every hop, fails closed)
demo/         register / resolve / tamper / spoof / contest / exit / run_all / run_local.sh
explorer/     self-contained protocol explorer (static-hostable; real in-process crypto)
schemas/      JSON Schemas for every artefact
tests/        74 unit + integration tests
docs/         design note, A2A mapping, diagrams
```

## Testing

```bash
make test         # or: uv run pytest -q
make lint         # ruff check + format --check
```

74 tests cover canonicalisation, signed records, did:key, AgentAddr tamper
detection, VC issue/verify (untrusted-issuer / tamper / expiry), the facts host,
contestation standing, self-sovereign exit (severance), the resolver walk, and the
A2A projection.

## Protocol explorer & diagrams

A self-contained visual walk-through of the resolution flow, with **real in-process
crypto** (Ed25519/JCS, W3C VCs, severance) — no dependency on the other services.
**Live:** <https://anivar.github.io/nanda-correction-surface/>

```bash
make explorer        # → http://localhost:8090   (or: docker compose up → :8090)
```

Scenarios — `resolve · privacy · tamper · spoof · contest · exit` — are grouped as
the **NANDA paper** (core) and **this work** (correction surface). Each plays as a
**swimlane sequence diagram** with a media-player step-through (play/pause, arrow
keys, click a step), a plain-English line on every step above the precise mechanism,
and hover **glossary** tooltips. A **"Where NANDA sits"** panel places the work on the
agent-stack ladder (identity → delegation → intent → continuity → consequence) and
links every standard and steward body (W3C, IETF, OpenID, FIDO, OASIS, OWASP, Linux
Foundation/AAIF, NIST …) to its primary source. The amber boundary marks the
correction-surface extension; operator-side authorisation is shown as cited context.

It hosts with **no backend** (e.g. GitHub Pages or any static domain):

```bash
uv run python -m explorer.build_static   # precompute explorer/static/data/*.json
# then publish explorer/static/ as-is (relative paths; works under a subpath)
```

Architecture, resolution sequence, the layer/boundary model and the exit flow are in
**[docs/diagrams.md](docs/diagrams.md)** (Mermaid).

## Scope & next steps

Deliberately out of scope for this prototype (noted in the design note):
adaptive/rotating endpoint resolution (Tier 3 routing), CRDT cross-registry
federation, a real VC Status List (revocation is stubbed), real standing
infrastructure (stubbed via agent-signed receipts), persistence, and production
hardening. The natural next steps: a Bitstring Status List service, `did:web`
issuers alongside `did:key`, mutually-signed interaction logs for stronger
standing, and an adaptive resolver.

## How AI tooling was used

Built with an AI coding assistant as the primary tool. I used it to (a) read and verify the
paper and current standards against primary sources (W3C VC 2.0, RFC 8785/8032,
did:key, the OpenID AuthZEN/AARP/COAZ announcement) before writing code, (b)
scaffold and implement the services and tests, and (c) keep the commit history
incremental. All cryptography uses established libraries (`cryptography`,
`PyJWT`, `rfc8785`) — no primitives were hand-rolled. The architecture, the
correction-surface design, and the framing are the author's.

## References

Protocol & standards:
- NANDA Index — arXiv:2507.14263 (v0.3) — the protocol this prototype implements
- RFC 8785 (JCS), RFC 8032 (Ed25519), RFC 8037 (OKP JWK)
- W3C Verifiable Credentials Data Model 2.0; Securing VCs with JOSE/COSE; did:key
- Google A2A Agent Card; OpenID AuthZEN Authorization API 1.0 (Final, Jan 2026),
  AARP & COAZ Working Group Drafts (15 June 2026); OAuth Transaction Tokens
  (draft-ietf-oauth-transaction-tokens) and Transaction Tokens for Agents
  (draft-araut-oauth-transaction-tokens-for-agents) — operator-side authorisation (context)

Background (the correction-surface framing):
- A. Aravind, *Corrigibility as a Structural Precondition for Digital Public
  Infrastructure: A Cybernetic Framework* — doi:10.2139/ssrn.6059075
- A. Aravind, *Epistemic Capture and the Action Boundary: Corrigibility for Learned
  and Agentic Public Infrastructure* — doi:10.2139/ssrn.6669318
- See `CITATION.cff` to cite this implementation.
```
