# AgentFence

> **Authorization that follows the action.**

An AI agent does not possess a vague permission to use a capability. It possesses a
narrowly scoped authorization to perform **one action, on one resource, from one origin,
inside one task** — and the execution boundary verifies those bindings again at the
moment of use.

```
"Agent is authorized"
        is materially different from
"This exact action is authorized in this exact execution context."
```

AgentFence demonstrates the second model, and demonstrates that the first one is not
sufficient.

---

## The problem this addresses

Most agent platforms answer the question *"is this agent allowed to use this tool?"*
That answer is true, and it is not sufficient.

A tool-scoped permission (`customer.read`) says nothing about **which** customer, **for
which** task, **from** which system, **before** which deadline. A long-running agent, a
prompt-injected instruction, or a misconfigured retry can all take a capability that is
legitimately granted and use it in a context nobody authorized.

AgentFence's position: **the authorization must be bound to the execution context, and
that binding must be re-verified at the execution boundary.** A capability check alone
leaves the interesting question unanswered — *"can this specific effect happen right
now?"*

### Honest scope

This does **not** make A2A or MCP insecure, does not solve prompt injection, is not an
IAM replacement, is not a complete security platform, and is not first-of-kind.

Modern agent protocols leave important details of in-task authorization scope, validity,
revocation, and execution enforcement to implementations and credential issuers. A2A
1.0 §7.6.4 states it does not define the scope, representation, validity, or revocation
semantics of in-task authorization. **AgentFence demonstrates one concrete approach for
making those semantics explicit and enforced.**

A narrow authorization binding does not by itself stop an injection: an injected
instruction can still *ask* for an authorized action. What it does is ensure the action
that actually runs is the one that was authorized, and that the request is provably
non-transferable.

---

## How it works

Five fields define the context. All five are bound, and all five are re-checked.

| Field | Bound to | Example |
|---|---|---|
| **action / capability** | `agentfence/capability` | `customer.read` |
| **resource** | `agentfence/resource` | `customer/123` |
| **origin** | `agentfence/origin` | `CRM-A` |
| **task** | `agentfence/task` | `TASK-184` |
| **validity window** | `authz_valid_from` → `authz_expires` | 300 s |

### The gate

Every execution runs the same fixed pipeline. There is no other path to a capability,
and the stages are ordered so the *most specific* failure is reported first — a
capability swap reports `CAPABILITY_MISMATCH`, not a generic policy denial.

| # | Stage | Fail-closed behaviour |
|---|---|---|
| 0 | Schema | malformed request → deny |
| 1 | Authorization present | missing auth → deny |
| 2 | **Integrity** | SHA-256 mismatch → deny |
| 3 | Registries | unknown principal/agent/capability/origin → deny (**no default allow**) |
| 4 | Validity window | expired or not-yet-valid → deny |
| 5 | **Policy lookup** | no rule → deny (**no default allow**) |
| 6 | **Bindings** | any of the 5 fields differs → deny |
| 7 | Policy effect | DENY / REQUIRE_APPROVAL → not executed |
| 8 | Approval | missing/unmatched approval → deny |
| 9 | Execute | only reachable if 0–8 all passed |

**The LLM is never the authorization authority.** It may *propose* an action. A
deterministic pipeline decides. The browser renders the gate's response; it decides
nothing.

### Evidence

Every decision — allow or deny — emits a receipt containing the receipt ID, the gate
result with its stage, the canonical request and authorization, the recomputed integrity
values, the approval ID, a SHA-256 evidence hash, and the exact human-readable reason.
The receipt hash is recomputable by anyone with the receipt, so the record is
independently checkable rather than merely asserted.

---

## Try it

```bash
git clone https://github.com/frostyjay7813/AgentFence
cd AgentFence
python -m pytest tests/ -q     # 88 tests
python serve.py                # http://127.0.0.1:8099
```

Then open the demo and click through the attacks. The four substitutions each produce a
specific denial:

```
Execute valid action   -> EXECUTION ALLOWED            "Northwind Traders"
Change resource        -> EXECUTION DENIED  RESOURCE_MISMATCH
Change action          -> EXECUTION DENIED  CAPABILITY_MISMATCH
Change origin          -> EXECUTION DENIED  ORIGIN_MISMATCH
Replay task            -> EXECUTION DENIED  TASK_CONTEXT_MISMATCH
```

Full AWS deployment (two console steps, ~10 minutes):
**[`submission/AWS_DEPLOY_STEPS.md`](submission/AWS_DEPLOY_STEPS.md)**

---

## Why it is built this way

**Deterministic, not probabilistic.** A model can be asked whether a request matches an
authorization. It can be wrong in a way that is hard to audit. A byte-compared,
SHA-256-sealed binding cannot be wrong quietly.

**Fail-closed everywhere.** An unknown capability, an unknown origin, a missing policy
rule, and an absent approval all deny. There is no permissive fallback anywhere in the
gate — this is exactly where AIF's own policy layer failed its own probe (6 of 9
consequential intents passed, including wiring money and exfiltrating credentials,
because the rule set was a case-insensitive substring match with no deny-by-default).

**Least privilege in the template.** The Lambda role grants exactly two DynamoDB
actions on exactly one table. No `AdministratorAccess`, no wildcard resource.

**Zero third-party runtime dependencies.** The Lambda imports only the Python standard
library, so there is no dependency supply chain to attack and nothing to bundle.

**The demo cannot lie.** The UI has no client-side allow path. Every result it shows is
the literal response from the gate.

---

## Documentation

| File | Purpose |
|---|---|
| [`submission/AWS_DEPLOY_STEPS.md`](submission/AWS_DEPLOY_STEPS.md) | Exact console deployment + the live verification checklist |
| [`submission/ARCHITECTURE.md`](submission/ARCHITECTURE.md) | Stage-by-stage design and the AWS-vs-AgentFence split |
| [`submission/SECURITY_TESTS.md`](submission/SECURITY_TESTS.md) | Every test, what it asserts, and the observed result |
| [`submission/BUILDER_CENTER.md`](submission/BUILDER_CENTER.md) | Builder Center submission text |
| [`evidence/`](evidence/) | Verification logs, coding-agent proof, screenshots |

---

## License

**Apache License 2.0** — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Chosen deliberately for a security product in a commercial lane:

- **Express patent grant** (§3) with patent-litigation termination — meaningful when the
  subject matter is authorization and security, where patent risk is real.
- **Trademark protection** (§6): you may reuse the code, but "AgentFence" stays yours.
  Anyone can build a commercial product on this; they cannot ship under your name.
- **Zero third-party runtime dependencies**, so redistribution carries no additional
  attribution obligation. `NOTICE` records that explicitly.

Copyright 2026 AgentFence contributors. The licence and `NOTICE` ship inside the
deployment package, so anyone who receives `function.zip` receives the terms too.

---

## Status

| Item | State |
|---|---|
| Policy engine + gate + receipts | Complete, 88/88 tests passing |
| Demo (single-page, single-origin) | Complete |
| CloudFormation + packaging | Complete, template validates, zip verified from the extracted archive |
| Live AWS URL | Pending operator console deployment (no credentials in this environment) |
| Builder Center post | Drafted, publish after the URL is live |

---

*Built with a coding agent (Hermes) — see [`evidence/coding-agent/`](evidence/coding-agent/).*
