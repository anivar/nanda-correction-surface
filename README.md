# NANDA Index — working prototype

A runnable prototype of the core resolution flow from
*Beyond DNS: Unlocking the Internet of AI Agents via the NANDA Index and Verified AgentFacts*
(Raskar et al., [arXiv:2507.14263](https://arxiv.org/pdf/2507.14263), v0.3), plus one focused
extension: a **contestation record** — the affected-party half of the trust object that the
paper leaves out.

> Status: scaffolding in progress. This README is filled in as the build lands.

## Quick start

```bash
docker compose up --build -d                 # index + 2 facts hosts + agent runtime
docker compose --profile demo run --rm demo  # the full end-to-end demo
```

No Docker? A local runner is provided:

```bash
./demo/run_local.sh
```

## What it shows

`AgentName → Index → AgentAddr → AgentFacts → endpoint`, with every hop printed and
cryptographically verified, failing closed on any tampering or forgery.

(Full architecture, verification rationale, and scope notes follow once the build is complete.)
