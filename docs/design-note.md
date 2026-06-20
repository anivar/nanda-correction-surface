# Design note

This is the "why" behind the prototype: the verification choices, the Level-2
extension, and where it sits in the wider standards landscape. The brief says
choosing the verification point is part of the exercise — so this is where I make
that reasoning explicit.

## 1. Verification: match the mechanism to the tier's volatility

The paper splits the architecture by *how fast each layer changes*. I made the
verification mechanism follow that same split, because the trade-offs differ:

| Tier | Artefact | Churn | Mechanism | Why |
|---|---|---|---|---|
| 1. Lean index | AgentAddr | low, heavily cached | **detached Ed25519 over RFC 8785 JCS** | The record must be tiny, cacheable, and redistributable without re-querying the index. A detached signature over canonical bytes needs no envelope and no JOSE parser to verify; the signed payload is exactly the human-readable JSON. Ed25519 is the smallest full-security signature with no nonce-reuse foot-gun. |
| 2. AgentFacts | provider VC + auditor VC | independent, frequent | **W3C Verifiable Credentials as JWTs (vc-jose-cose)** | Facts must verify *independently of the host that serves them* (this is what makes the privacy path safe), support *plural issuers* (provider self-claim + independent auditor), and carry validity/revocation. That is exactly what VCs are for. |

Two different mechanisms, deliberately. A single mechanism everywhere would
either bloat the lean record (a full VC per index entry) or under-serve the
metadata (a bare signature can't express multi-issuer trust or revocation).

Concretely, this buys two distinct, independently-checkable failures:

- **Tamper** (Tier 1): mutate any AgentAddr field — redirect the facts pointer,
  inflate the ttl — and the client recomputes the JCS bytes, the Ed25519
  signature fails, resolution stops. Crucially the client **pins** the resolver
  DID: a *valid* signature is not enough, it must be the *expected* signer, so an
  attacker who re-signs with their own key is still rejected.
- **Spoof** (Tier 2): present a credential from an untrusted issuer (rejected by
  trust policy) or a mutated credential from a trusted issuer (rejected by the
  JWS signature). Note the layering this exposes: the index will sign a *pointer*
  for anyone — it is a low-trust quilt — but the *facts* must come from an issuer
  the client trusts.

### Substrate-neutral identity

All issuers use `did:key` — self-certifying, so a verifier recovers the public
key from the DID with no network call and no central anchor. This is a deliberate
stance: plural issuers, each independently verifiable, no mandatory root. A
production deployment could mix `did:web` (domain-anchored issuers) without
changing the verification code.

## 2. Level 2 — the contestation dual (the half the paper leaves out)

The required Level-1 core was built and passing end-to-end first; the
contestation record was scoped on top of it.

AgentFacts is a **one-way** trust object. Read the stack by *who holds the lever*
at each layer:

```
  CORRECTION / AFFECTED-PARTY        lever: the governed party   ← ABSENT in the paper
  (contest, counter-attest)          ← THIS IS LEVEL 2
  ----------------------------------------------------------------
  AUTHORISATION (AuthZEN)            lever: PDP operator + approver   [context only]
  ----------------------------------------------------------------
  NANDA: resolution / facts / index  lever: resolvers, issuers, registries
  ----------------------------------------------------------------
  ROOT TRUST                         lever: root authority
```

Every lever in NANDA sits with an operator, an issuer, or a registry. **None sits
with the party an agent acts upon.** Issuers attest *to* the agent; nothing
carries a claim *back* from the counterparty. The contestation record is the
affected-party half of the same trust object: a signed counter-claim that travels
with the facts and that the client surfaces *alongside* the issuers' claims —
never silently overriding either side.

The hard problem is **standing** (who may contest?). Building real standing is a
project of its own, so it is stubbed with a verifiable, non-circular primitive:

- an **interaction receipt** signed by the *agent's own key* acknowledges an
  interaction with a counterparty under an interaction id — the contestant cannot
  forge this;
- a **contestation** signed by the *affected party* embeds that receipt;
- the client grants standing iff the contestant's signature verifies, the
  embedded receipt's (agent) signature verifies, and the receipt names this
  contestant for the referenced interaction.

In plain terms: *you may contest an interaction the agent itself acknowledged
having with you.*

## 3. Where this is heading (standards context — not built here)

Authorisation — "may this action proceed?" — is a separate layer **above**
identity/discovery, and it is moving fast:

- The **OpenID AuthZEN Authorization API** reached **Final Specification on
  12 January 2026** (Implementer's Draft 01 was November 2024). It standardises
  the PEP→PDP access-evaluation call over a Subject–Action–Resource–Context model.
- On **15 June 2026**, the AuthZEN WG approved two Working Group Drafts: **AARP**
  (AuthZEN Access Request and Approval Profile — reframing a denial into "what is
  required before policy can authorise this", i.e. approvable-with-prerequisites)
  and **COAZ** (AuthZEN Profile for Model Context Protocol Tool Authorization —
  mapping MCP tool calls to the AuthZEN model).
  Source: <https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/>

These define how an *operator/approver* gates an action. They still do not give
the *governed party* a voice — which is the gap the contestation dual probes.
NANDA itself points this way: it cites the LOKA Protocol for future decentralised
trust/reputation work, and the contestation record is a minimal, concrete step in
that direction. (AuthZEN / Biscuit / SCITT are landscape context for discussion;
they are deliberately **not** wired into the code — the prototype demonstrates one
principled primitive well rather than three integrations half-done.)

## 4. Honest limitations

- **Privacy path moves trust, it doesn't remove it.** The neutral host still sees
  the access; what it buys is that the *agent's own domain* doesn't learn who
  resolved it. Production would add Tor/IPFS/mix-net hosting and request batching.
- **Standing is stubbed.** A hostile agent could withhold receipts. Production
  standing would use a mutually-signed interaction log or a third-party notary.
- **Revocation is stubbed** as a credential-id set checked client-side, not a
  Bitstring Status List service.
- **State is in-memory** per service — register then resolve in one run. No
  persistence layer, no CRDT cross-registry federation (out of scope per the paper
  appendix).
- **The agent runtime is a trivial stand-in** — the point is the resolution and
  trust path, not the agent's cleverness.
