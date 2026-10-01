# AgentFence — Authorization that follows the action

**Category:** `#commercial-potential`
**Lane:** `#startups`

> An AI agent does not hold a permission to use a capability. It holds an authorization
> to perform **one action, on one resource, from one origin, inside one task** — and the
> execution boundary re-verifies that context at the moment of use.

**Live URL:** `<PASTE AFTER DEPLOYMENT>`
**Repository:** https://github.com/frostyjay7813/AgentFence

---

## The problem

The standard agent-platform model asks *"is this agent allowed to use this tool?"* That
answer is true, and it is not sufficient.

A capability-scoped permission — `customer.read` — says nothing about **which** customer,
**for which** task, **from** which system, **before** which deadline. Four requests all
sit under that same permission:

| Request | Same capability? | Same authority? |
|---|---|---|
| read `customer/123` from `CRM-A` for `TASK-184` | yes | **yes** |
| read `customer/999` from `CRM-A` for `TASK-184` | yes | **no** |
| read `customer/123` from `CRM-B` for `TASK-184` | yes | **no** |
| read `customer/123` from `CRM-A` for `TASK-185` | yes | **no** |

Every production hazard — the long-running agent, the retried step, the orchestrator
mix-up, the injected instruction — lives in the three "no" rows. The question that
actually matters is not *"can this agent use this tool?"* but *"can this specific effect
happen right now, in this context?"*

## What AgentFence does

It binds an authorization to **five fields plus a validity window**, and re-verifies all
of them at the execution boundary:

```
action/capability · resource · origin · task · validity window
```

Each value is sealed with a SHA-256 integrity value and compared with
`hmac.compare_digest`. Every execution traverses one fixed, fail-closed pipeline, and
every decision — allow **and** deny — emits a verifiable receipt.

### Watch it work

Click **Launch Interactive Demo**, then apply each attack:

```
Execute valid action   ->  EXECUTION ALLOWED       Northwind Traders
Change resource        ->  EXECUTION DENIED        RESOURCE_MISMATCH
Change action          ->  EXECUTION DENIED        CAPABILITY_MISMATCH
Change origin          ->  EXECUTION DENIED        ORIGIN_MISMATCH   (expected vs received)
Replay task            ->  EXECUTION DENIED        TASK_CONTEXT_MISMATCH
Expire authorization   ->  EXECUTION DENIED        AUTHORIZATION_EXPIRED
Tamper integrity       ->  EXECUTION DENIED        INTEGRITY_MISMATCH
```

The authorization is granted once. Every subsequent attempt to reuse it **outside the
exact context it was issued for** is refused with a specific, machine-readable reason.

The browser decides nothing — it renders the server's gate response. Every attempt
produces a receipt answering *who acted, what happened, why it was allowed or denied,
and what proves it*.

## Why it is built this way

**Deterministic, not probabilistic.** A model asked "does this request match this
authorization?" can be wrong quietly. A sealed, byte-compared binding cannot.

**Fail-closed with no exceptions.** Unknown capability, unknown origin, missing policy
rule, absent approval, unreadable authorization — all deny. There is no permissive
fallback anywhere in the pipeline. This is deliberate: substring/pattern policy matching
has a well-documented failure mode where consequential requests pass because no rule
matched.

**Honest about stage ordering.** Binding verification runs *before* policy evaluation, so
a swapped capability reports `CAPABILITY_MISMATCH` rather than a generic `POLICY_DENY` —
more precise, and it does not leak policy posture to an attacker.

**Least privilege in the template.** The Lambda role gets exactly two DynamoDB actions on
exactly one table. No `AdministratorAccess`, no wildcard resource.

**No dependencies to attack.** The Lambda imports only the Python standard library.

## AWS architecture

| Service | Role |
|---|---|
| **Lambda** (Python 3.12, arm64) | Runs the deterministic gate |
| **API Gateway** | Public HTTPS surface |
| **DynamoDB** | Receipt persistence — on-demand, 90-day TTL, PITR, SSE |
| **CloudWatch Logs** | Gate decisions, 14-day retention |
| **IAM** | Scoped execution role (2 actions, 1 table) |
| **CloudFormation** | Reproducible stack, 193-line template |

The Lambda serves the demo page itself, so the application is **one public URL with no
CORS and no CloudFront setup**.

The security claim is AgentFence's own logic — canonicalization, integrity, binding
verification, gate order, receipts — not an AWS feature. No service was added for
marketing value.

## Verification

```
96/96 tests passing        bypass, fail-closed, integrity, approval, receipts, HTTP
0 credential patterns      scripts/secret_scan.py on the public repo
Live artifact tested       executed from the extracted function.zip, not the dev tree
```

Every denial in this post is captured output in
[`evidence/runtime_evidence.json`](../evidence/runtime_evidence.json).

## Honest limitations

This is a demonstrator for one narrow claim, and it is stronger for saying so:

- **Integrity values are unkeyed.** They detect tampering, not a determined forger who
  knows the scheme. Keyed signing (Ed25519 / KMS) is the documented next step.
- **The trust anchor is the issuer.** AgentFence proves the authorization is intact and
  contextually valid; it does not prove *who issued* it.
- **It does not solve prompt injection.** Binding authorization does not stop an injected
  instruction from *asking* for an authorized action — it guarantees the action that runs
  is the one that was authorized.
- **Not first-of-kind.** A2A 1.0 §7.6.4 explicitly leaves in-task authorization scope,
  validity, and revocation semantics to implementations. AgentFence demonstrates one
  concrete approach, not the only one.
- **Not an IAM replacement, not a complete security platform.**
- **The capability layer is deterministic and local.** Real connectors come next.

## Why this is a business, not a demo

Every production agent deployment eventually asks *"what did it actually do, and was that
allowed?"* Today that question is answered by reading logs and reconstructing intent —
manually, per incident. AgentFence is the artifact that answers it mechanically.

The wedge is deliberately narrow: it is not an agent platform, not a new model, not a
dashboard. It is one decision point at the boundary where effects become real, and it is
the piece a platform team cannot get from a model provider.

**Next:** issuer signatures and an issuer registry, delegation with attenuation (the
XACML delegation profile is prior art), and connector-level enforcement where the real
credentials live.

---

## Open source

**Apache License 2.0** — [`LICENSE`](../LICENSE), [`NOTICE`](../NOTICE).
Copyright 2026 AgentFence contributors.

Zero third-party runtime dependencies, so the licence and NOTICE travel with the
deployment package and redistribution carries no additional obligations. Apache-2.0 was
chosen for its express patent grant and because its trademark clause keeps the
AgentFence name reserved — anyone may build commercially on this; nobody may ship it
under our brand.

---

*Built with a coding agent (Hermes). Development process and verification evidence:
[`evidence/coding-agent/`](../evidence/coding-agent/).*
