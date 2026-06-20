"""The NANDA client — resolve an AgentName, verifying and printing every hop.

This is the component the brief centres on: "a client should be able to resolve
an agent name and receive something it can verify and act on." It walks

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

from dataclasses import dataclass, field
from typing import Optional

import httpx

from nanda_core import crypto, vc
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
    auditor_credential: Optional[dict] = None
    contestations: list = field(default_factory=list)
    endpoint: Optional[str] = None
    action_response: Optional[dict] = None


class NandaClient:
    def __init__(self, policy: TrustPolicy, index_url: str, *, verbose: bool = True,
                 timeout: float = 10.0):
        self.policy = policy
        self.index_url = index_url.rstrip("/")
        self.verbose = verbose
        self._http = httpx.Client(timeout=timeout)

    # --- output ---------------------------------------------------------------
    def _say(self, line: str = "") -> None:
        if self.verbose:
            print(line)

    # --- the resolution walk --------------------------------------------------
    def resolve(self, agent_name: str, *, path: str = "primary", act: bool = True) -> ResolveResult:
        self._say(C.rule(f"Resolve  {agent_name}   ({path} path)"))

        # Hop 1 — index lookup -> signed AgentAddr
        self._say(C.hop(1, "Index lookup → AgentAddr"))
        signed_addr = self._get_json(f"{self.index_url}/resolve", params={"name": agent_name},
                                     what="AgentAddr")
        self._say(C.info(f"agent_id           {signed_addr.get('agent_id')}"))
        self._say(C.info(f"primary_facts_url  {signed_addr.get('primary_facts_url')}"))
        self._say(C.info(f"private_facts_url  {signed_addr.get('private_facts_url')}"))
        self._say(C.info(f"ttl                {signed_addr.get('ttl')}s"))
        self.verify_agentaddr(signed_addr)

        # Hop 2 — choose the facts URL for the requested path
        self._say(C.hop(2, "Select AgentFacts source"))
        facts_url, host_role = self._select_facts_url(signed_addr, path)

        # Hop 3 — fetch AgentFacts bundle from the (untrusted) host
        self._say(C.hop(3, f"Fetch AgentFacts  [{host_role} host]"))
        self._say(C.info(f"GET {facts_url}"))
        bundle = self._get_json(facts_url, what="AgentFacts bundle")

        # Hop 4 — verify the provider credential (required)
        self._say(C.hop(4, "Verify provider credential (W3C VC)"))
        provider_cred = self._verify_credential(bundle.get("provider_vc"), "provider")
        subject = provider_cred["credentialSubject"]
        self._say(C.info(f"label        {subject.get('label')}"))
        self._say(C.info(f"version      {subject.get('version')}"))
        self._say(C.info(f"skills       {[s.get('id') for s in subject.get('skills', [])]}"))

        # Hop 5 — verify the auditor credential (corroboration) + threshold
        self._say(C.hop(5, "Verify auditor credential (independent issuer)"))
        auditor_cred = None
        verified_issuers = {provider_cred["issuer"]}
        if bundle.get("auditor_vc"):
            auditor_cred = self._verify_credential(bundle.get("auditor_vc"), "auditor")
            verified_issuers.add(auditor_cred["issuer"])
            ev = auditor_cred["credentialSubject"].get("evaluations", {})
            self._say(C.info(f"performanceScore {ev.get('performanceScore')}  "
                             f"availability90d {ev.get('availability90d')}"))
        else:
            self._say(C.warn("no auditor credential present (corroboration only)"))
        self._enforce_threshold(verified_issuers)

        # Hop 6 — surface contestations (Level 2; full verification added there)
        self._say(C.hop(6, "Surface contestations (affected-party claims)"))
        contestations = self._surface_contestations(bundle, subject.get("id"))

        # Hop 7 — act on the verified endpoint
        endpoint, action = None, None
        if act:
            self._say(C.hop(7, "Act on verified endpoint"))
            endpoint, action = self._act(subject)

        self._say(C.ok(C.bold("resolution complete — every hop verified")) + "\n")
        return ResolveResult(
            agent_name=agent_name, path=path, agent_addr=signed_addr, facts_url=facts_url,
            facts_host_role=host_role, provider_credential=provider_cred,
            auditor_credential=auditor_cred, contestations=contestations,
            endpoint=endpoint, action_response=action,
        )

    # --- hop helpers ----------------------------------------------------------
    def verify_agentaddr(self, signed: dict) -> None:
        """Verify a signed AgentAddr against the pinned resolver. Public so the
        tamper demo can feed it a mutated record. Raises VerificationFailure."""
        proof = signed.get("proof") or {}
        signer_did = str(proof.get("verificationMethod", "")).split("#", 1)[0]
        # Pin: a valid signature is not enough — it must be the EXPECTED resolver.
        if signer_did != self.policy.resolver_did:
            self._say(C.fail(f"AgentAddr signer {signer_did or '<none>'} "
                             f"≠ pinned resolver {self.policy.resolver_did}"))
            raise VerificationFailure("AgentAddr not signed by the pinned resolver")
        try:
            pub = decode_did_key(signer_did)
        except ValueError as exc:
            raise VerificationFailure(f"bad resolver did:key: {exc}") from exc
        if not crypto.verify_record(signed, pub):
            self._say(C.fail("AgentAddr signature INVALID — record was tampered with"))
            raise VerificationFailure("AgentAddr signature invalid")
        self._say(C.ok("AgentAddr signature valid, signed by the pinned index resolver"))

    def _select_facts_url(self, signed: dict, path: str) -> tuple[str, str]:
        if path == "private":
            url = signed.get("private_facts_url")
            if not url:
                raise VerificationFailure("privacy path requested but no private_facts_url")
            self._say(C.ok("privacy path: AgentFacts fetched from a NEUTRAL host"))
            self._say(C.info("the agent's own domain never sees this resolution → requester stays unlinkable"))
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
        if self.policy.is_revoked(cred):
            self._say(C.fail(f"{label} credential REVOKED ({cred.get('id')})"))
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

    def _surface_contestations(self, bundle: dict, agent_did: str) -> list:
        contestations = bundle.get("contestations", []) or []
        if not contestations:
            self._say(C.info("none on record"))
        else:
            self._say(C.warn(f"{len(contestations)} contestation(s) attached "
                             f"(verified and surfaced in Level 2)"))
        return contestations

    def _act(self, subject: dict) -> tuple[Optional[str], Optional[dict]]:
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
            raise VerificationFailure(f"{what} lookup failed: HTTP {exc.response.status_code}") from exc
        except httpx.HTTPError as exc:
            raise VerificationFailure(f"{what} lookup failed: {exc}") from exc
