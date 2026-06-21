"""The NANDA client — resolve an AgentName, verifying and printing every hop.

This is the heart of the prototype: a client resolves an agent name and receives
something it can verify and act on. It walks

    AgentName → Index → AgentAddr → AgentFacts → endpoint

and at each hop it prints what it received and the result of verifying it. It
**fails closed**: the first verification that does not pass raises
VerificationFailure and resolution stops — nothing unverified is ever acted on.

Two resolution paths are supported (paper §V.D):
  - "primary" : fetch AgentFacts from the provider's own domain
  - "private" : fetch from the neutral host, so the agent's domain never learns
                who resolved it (requester privacy)
Both verify identically, because AgentFacts are signed by their issuers, not the host.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

import httpx

from nanda_core import contest, crypto, severance, vc
from nanda_core.didkey import decode_did_key
from nanda_core.trust import TrustPolicy

from . import console as C


class VerificationFailure(Exception):
    """Any hop that does not verify. The client stops here — fail closed."""


@dataclass
class ResolveResult:
    agent_name: str
    path: str
    agent_addr: dict
    facts_url: str
    facts_host_role: str
    provider_credential: dict
    auditor_credential: dict | None = None
    contestations: list = field(default_factory=list)
    endpoint: str | None = None
    action_response: dict | None = None


class NandaClient:
    def __init__(
        self,
        policy: TrustPolicy,
        index_url: str,
        *,
        revocation_url: str | None = None,
        verbose: bool = True,
        timeout: float = 10.0,
    ):
        self.policy = policy
        self.index_url = index_url.rstrip("/")
        self.revocation_url = revocation_url  # live VC-Status-List stub, refreshed per resolve
        self.verbose = verbose
        self._http = httpx.Client(timeout=timeout)
        self._revoked_live: dict[str, str] = {}  # credential/status id -> revoking issuer did

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> NandaClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # --- output ---------------------------------------------------------------
    def _say(self, line: str = "") -> None:
        if self.verbose:
            print(line)

    # --- the resolution walk --------------------------------------------------
    def resolve(self, agent_name: str, *, path: str = "primary", act: bool = True) -> ResolveResult:
        self._say(C.rule(f"Resolve  {agent_name}   ({path} path)"))
        self._refresh_revocations()

        # Hop 1 — index lookup -> signed AgentAddr
        self._say(C.hop(1, "Index lookup → AgentAddr"))
        signed_addr = self._get_json(
            f"{self.index_url}/resolve", params={"name": agent_name}, what="AgentAddr"
        )
        self._say(C.info(f"agent_id           {signed_addr.get('agent_id')}"))
        self._say(C.info(f"registration_type  {signed_addr.get('registration_type', 'native')}"))
        self._say(C.info(f"primary_facts_url  {signed_addr.get('primary_facts_url')}"))
        self._say(C.info(f"private_facts_url  {signed_addr.get('private_facts_url')}"))
        self._say(C.info(f"ttl                {signed_addr.get('ttl')}s"))
        self.verify_agentaddr(signed_addr)

        # Hop 2 — choose the facts URL (following the enterprise registry, if routed)
        self._say(C.hop(2, "Select AgentFacts source"))
        facts_url, host_role = self._resolve_facts_url(signed_addr, path)

        # Hop 3 — fetch AgentFacts bundle from the (untrusted) host
        self._say(C.hop(3, f"Fetch AgentFacts  [{host_role} host]"))
        self._say(C.info(f"GET {facts_url}"))
        bundle = self._get_json(facts_url, what="AgentFacts bundle")

        # Exit gate — refuse immediately if the subject has SEVERED this identity.
        # Checked against the index-bound (signed) agent_did + agent_id, before
        # trusting facts, so a severance cannot be replayed onto another entry.
        self._check_severance(bundle, signed_addr.get("agent_did"), signed_addr.get("agent_id"))

        # Hop 4 — verify the provider credential (required)
        self._say(C.hop(4, "Verify provider credential (W3C VC)"))
        provider_cred = self._verify_credential(bundle.get("provider_vc"), "provider")
        subject = provider_cred["credentialSubject"]
        # Bind the verified VC subject to the signed index record: an untrusted host
        # must not be able to serve a different agent's (validly-issued) VC here.
        # agent_did is guaranteed present (enforced in verify_agentaddr), so this is
        # an equality check that always runs — never silently skipped.
        expected_did = signed_addr["agent_did"]
        if subject.get("id") != expected_did:
            self._say(
                C.fail(
                    f"provider VC subject {subject.get('id')} ≠ AgentAddr agent_did {expected_did}"
                )
            )
            raise VerificationFailure("provider VC subject does not match the signed AgentAddr")
        self._say(C.info(f"label        {subject.get('label')}"))
        self._say(C.info(f"version      {subject.get('version')}"))
        self._say(C.info(f"skills       {[s.get('id') for s in subject.get('skills', [])]}"))

        # Hop 5 — verify the auditor credential (corroboration) + threshold
        self._say(C.hop(5, "Verify auditor credential (independent issuer)"))
        auditor_cred = None
        verified_issuers = {provider_cred["issuer"]}
        if bundle.get("auditor_vc"):
            auditor_cred = self._verify_credential(bundle.get("auditor_vc"), "auditor")
            # The auditor must be attesting the SAME subject as the provider, or the
            # corroboration is meaningless (a host could pair a good agent's audit
            # with a different agent's facts).
            if auditor_cred["credentialSubject"].get("id") != subject.get("id"):
                self._say(C.fail("auditor VC subject ≠ provider VC subject"))
                raise VerificationFailure(
                    "auditor VC attests a different subject than the provider VC"
                )
            verified_issuers.add(auditor_cred["issuer"])
            ev = auditor_cred["credentialSubject"].get("evaluations", {})
            self._say(
                C.info(
                    f"performanceScore {ev.get('performanceScore')}  "
                    f"availability90d {ev.get('availability90d')}"
                )
            )
        else:
            self._say(C.warn("no auditor credential present (corroboration only)"))
        self._enforce_threshold(verified_issuers)

        # Hop 6 — surface contestations (the correction surface)
        self._say(C.hop(6, "Surface contestations (affected-party claims)"))
        contestations = self._surface_contestations(
            bundle, subject.get("id"), signed_addr.get("agent_id")
        )

        # Hop 7 — act on the verified endpoint
        endpoint, action = None, None
        if act:
            self._say(C.hop(7, "Act on verified endpoint"))
            endpoint, action = self._act(subject)

        self._say(C.ok(C.bold("resolution complete — every hop verified")) + "\n")
        return ResolveResult(
            agent_name=agent_name,
            path=path,
            agent_addr=signed_addr,
            facts_url=facts_url,
            facts_host_role=host_role,
            provider_credential=provider_cred,
            auditor_credential=auditor_cred,
            contestations=contestations,
            endpoint=endpoint,
            action_response=action,
        )

    # --- hop helpers ----------------------------------------------------------
    def verify_agentaddr(self, signed: dict) -> None:
        """Verify a signed AgentAddr against the pinned resolver. Public so the
        tamper demo can feed it a mutated record. Raises VerificationFailure."""
        proof = signed.get("proof") or {}
        signer_did = str(proof.get("verificationMethod", "")).split("#", 1)[0]
        # Pin: a valid signature is not enough — it must be the EXPECTED resolver.
        if signer_did != self.policy.resolver_did:
            self._say(
                C.fail(
                    f"AgentAddr signer {signer_did or '<none>'} "
                    f"≠ pinned resolver {self.policy.resolver_did}"
                )
            )
            raise VerificationFailure("AgentAddr not signed by the pinned resolver")
        try:
            pub = decode_did_key(signer_did)
        except ValueError as exc:
            raise VerificationFailure(f"bad resolver did:key: {exc}") from exc
        if not crypto.verify_record(signed, pub):
            self._say(C.fail("AgentAddr signature INVALID — record was tampered with"))
            raise VerificationFailure("AgentAddr signature invalid")
        # The signed pointer MUST carry the agent's did:key. It is the anchor that
        # binds the VC subject and the severance/exit gate to this exact identity;
        # without it those checks would have nothing to bind to, so fail closed
        # rather than resolve an unbindable record.
        if not signed.get("agent_did"):
            self._say(C.fail("AgentAddr has no agent_did — identity cannot be bound"))
            raise VerificationFailure("AgentAddr missing agent_did — cannot bind identity")
        self._say(C.ok("AgentAddr signature valid, signed by the pinned index resolver"))
        self._check_freshness(signed)

    def _check_freshness(self, signed: dict) -> None:
        """Honour the signed ttl using the signed issued_at anchor. Staleness is a
        cache concern, not tampering, so we warn rather than fail closed."""
        issued_at, ttl = signed.get("issued_at"), signed.get("ttl")
        if not issued_at or not isinstance(ttl, int):
            return
        try:
            issued = dt.datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
        except ValueError:
            return
        age = int((dt.datetime.now(dt.UTC) - issued).total_seconds())
        if age > ttl:
            self._say(C.warn(f"AgentAddr stale (age {age}s > ttl {ttl}s) — re-resolve"))

    def _refresh_revocations(self) -> None:
        """Pull the current revocation set (stubbed VC-Status-List). Revocation is
        dynamic state, so unlike the trust anchors it IS fetched at resolve time."""
        if not self.revocation_url:
            return
        try:
            data = self._get_json(self.revocation_url, what="revocation list")
        except VerificationFailure:
            # Fail closed: a transient outage (or a DoS on the status endpoint) must
            # NOT silently widen the trust surface by dropping known revocations, so
            # we retain the last good set rather than clearing it.
            self._say(C.warn("revocation list unavailable — retaining last known revocations"))
            return
        live: dict[str, str] = {}
        for r in data.get("revoked", []):
            cid, issuer, sig = r.get("credential_id"), r.get("issuer_did"), r.get("signature")
            # Only honour revocations signed by an issuer we trust (and, at use, by the
            # credential's OWN issuer — checked in _verify_credential).
            if not cid or issuer not in self.policy.trusted_issuers:
                continue
            try:
                if crypto.verify_bytes(
                    decode_did_key(issuer), crypto.b64u_decode(sig), cid.encode()
                ):
                    live[cid] = issuer
            except (ValueError, TypeError):
                continue
        self._revoked_live = live

    def _resolve_facts_url(self, signed: dict, path: str) -> tuple[str, str]:
        # Enterprise-routed entries take one extra hop through a registry.
        if signed.get("registration_type") == "enterprise" and signed.get(
            "enterprise_registry_url"
        ):
            reg_url = signed["enterprise_registry_url"]
            self._say(C.ok(f"enterprise-routed: via registry {reg_url}"))
            reg = self._get_json(reg_url, what="enterprise registry")
            url = reg.get("facts_url")
            if not url:
                raise VerificationFailure("enterprise registry returned no facts_url")
            self._say(C.info(f"registry → {url}"))
            return url, "enterprise"
        return self._select_facts_url(signed, path)

    def _check_severance(
        self, bundle: dict, agent_did: str | None, agent_id: str | None = None
    ) -> None:
        """Exit gate: if the subject has severed this identity (signed by its own
        key), prior authority is inexecutable — refuse, surfacing any successor.

        Bound to BOTH the signed agent_did and agent_id, so a valid severance filed
        against one registry entry cannot be replayed onto another that shares the
        same key."""
        sev = bundle.get("severance")
        if not sev or not agent_did:
            return
        if severance.verify_severance(
            sev, expected_agent_did=agent_did, expected_agent_id=agent_id
        ):
            successor = sev.get("successor_did")
            self._say(C.fail("identity SEVERED by its own key — prior authority inexecutable"))
            if successor:
                self._say(C.info(f"successor identity: {successor}"))
            raise VerificationFailure(
                "agent has severed this identity"
                + (f" (successor: {successor})" if successor else "")
            )
        self._say(C.warn("ignoring an invalid severance (not signed by this identity)"))

    def _select_facts_url(self, signed: dict, path: str) -> tuple[str, str]:
        if path == "private":
            url = signed.get("private_facts_url")
            if not url:
                raise VerificationFailure("privacy path requested but no private_facts_url")
            self._say(C.ok("privacy path: AgentFacts fetched from a NEUTRAL host"))
            self._say(
                C.info(
                    "the agent's own domain never sees this resolution → requester stays unlinkable"
                )
            )
            return url, "neutral"
        url = signed.get("primary_facts_url")
        if not url:
            raise VerificationFailure("no primary_facts_url in AgentAddr")
        self._say(C.ok("primary path: AgentFacts fetched from the provider domain"))
        return url, "primary"

    def _verify_credential(self, token, label: str) -> dict:
        if not token:
            self._say(C.fail(f"{label} credential missing"))
            raise VerificationFailure(f"{label} credential missing")
        try:
            cred = vc.verify_credential(token, trusted_issuers=self.policy.trusted_issuers)
        except vc.VCError as exc:
            self._say(C.fail(f"{label} credential REJECTED: {exc}"))
            raise VerificationFailure(f"{label} credential invalid: {exc}") from exc
        cred_id = cred.get("id")
        status_id = (cred.get("credentialStatus") or {}).get("id")
        issuer = cred.get("issuer")
        # A live revocation counts only if signed by the credential's OWN issuer.
        live_revoked = (
            self._revoked_live.get(cred_id) == issuer or self._revoked_live.get(status_id) == issuer
        )
        if self.policy.is_revoked(cred) or live_revoked:
            self._say(C.fail(f"{label} credential REVOKED ({cred_id})"))
            raise VerificationFailure(f"{label} credential revoked")
        self._say(C.ok(f"{label} VC verified — issuer {cred['issuer']} (host-independent)"))
        return cred

    def _enforce_threshold(self, verified_issuers: set[str]) -> None:
        missing = self.policy.required_issuers - verified_issuers
        if missing:
            self._say(C.fail(f"trust threshold not met; missing required issuers: {missing}"))
            raise VerificationFailure(f"required issuers missing: {missing}")
        if self.policy.required_issuers:
            self._say(C.ok("trust threshold met (all required issuers verified)"))

    def _surface_contestations(
        self, bundle: dict, agent_did: str, agent_id: str | None = None
    ) -> list:
        """Verify and surface affected-party counter-claims NEXT TO the issuer
        claims. The client never silently drops a contestation that has standing,
        and never trusts one that does not — both halves of the trust object are
        shown to the caller."""
        # De-duplicate by contestation_id so a replayed POST can't amplify one
        # complaint into an apparent flood.
        raw, seen = [], set()
        for c in bundle.get("contestations") or []:
            cid = c.get("contestation_id")
            if cid is None or cid in seen:
                continue  # drop malformed (no id) so it can't poison the dedup set
            seen.add(cid)
            raw.append(c)
        if not raw:
            self._say(C.info("none on record"))
            return []
        surfaced = []
        for c in raw:
            verdict = contest.verify_contestation(
                c, expected_agent_did=agent_did, expected_agent_id=agent_id
            )
            if verdict.valid:
                self._say(C.warn(f"CONTESTED [{verdict.category}] by {verdict.contestant}"))
                self._say(C.info(f"“{verdict.statement}”"))
                self._say(C.info(f"standing: {verdict.reason}"))
                surfaced.append(verdict)
            else:
                self._say(C.info(f"ignored unverifiable contestation: {verdict.reason}"))
        if surfaced:
            self._say(
                C.warn(
                    f"{len(surfaced)} verified contestation(s) surfaced "
                    f"alongside the issuers' claims"
                )
            )
        return surfaced

    def _act(self, subject: dict) -> tuple[str | None, dict | None]:
        endpoints = (subject.get("endpoints") or {}).get("static") or []
        if not endpoints:
            self._say(C.warn("no static endpoint to act on"))
            return None, None
        endpoint = endpoints[0]
        self._say(C.info(f"POST {endpoint}"))
        try:
            resp = self._http.post(endpoint, json={"input": "hello world", "task": "demo"})
            resp.raise_for_status()
            data = resp.json()
        except Exception as exc:  # noqa: BLE001 - action failure is not a trust failure
            self._say(C.warn(f"endpoint not reachable ({exc}); verification still succeeded"))
            return endpoint, None
        self._say(C.ok(f"acted on verified endpoint → {data.get('output')!r}"))
        return endpoint, data

    # --- http -----------------------------------------------------------------
    def _get_json(self, url: str, *, params: dict | None = None, what: str = "resource") -> dict:
        try:
            resp = self._http.get(url, params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as exc:
            raise VerificationFailure(
                f"{what} lookup failed: HTTP {exc.response.status_code}"
            ) from exc
        except httpx.HTTPError as exc:
            raise VerificationFailure(f"{what} lookup failed: {exc}") from exc
