# AgentFence — Architecture

## The one idea

> An agent does not hold a permission to use a capability. It holds an authorization to
> perform **one action, on one resource, from one origin, inside one task, before a
> deadline** — and the execution boundary re-verifies that context at the moment of use.

Everything below serves that sentence.

---

## Why this is not a capability check

The common model — "this agent may use `customer.read`" — is true and insufficient. A
tool-scoped permission cannot distinguish these four requests, all of which the same
permission nominally covers:

| Request | Same capability? | Same authority? |
|---|---|---|
| read `customer/123`, from `CRM-A`, for `TASK-184` | yes | **yes** |
| read `customer/999`, from `CRM-A`, for `TASK-184` | yes | **no** |
| read `customer/123`, from `CRM-B`, for `TASK-184` | yes | **no** |
| read `customer/123`, from `CRM-A`, for `TASK-185` | yes | **no** |

Long-running agents, retries, orchestrator mix-ups, and injected instructions all live
in the four "no" rows. The interesting question is not *"is this agent allowed to use
this tool?"* — it is *"can this specific effect happen right now, in this context?"*

### Honest limits

This does not make A2A or MCP insecure, does not solve prompt injection, is not an IAM
replacement, is not a complete security platform, and is not first-of-kind.

A2A 1.0 §7.6.4 states the protocol does not define the scope, representation, validity,
or revocation semantics of in-task authorization — those are left to implementations.
AgentFence demonstrates one concrete way to make them explicit and enforced.

**Binding the authorization does not prevent injection.** An injected instruction can
still *ask* for an authorized action. What binding guarantees is that the action that
runs is the one that was authorized, and that the request is provably non-transferable.
Blocking injection is a separate control (sanitizing untrusted input, separating
instruction from data) and AgentFence does not claim to do it.

---

## Data model

An **authorization** is a sealed statement. Five fields plus validity are bound:

```jsonc
{
  "authorization_id":  "AUTH-...",
  "principal":         "svc-research",      // who is acting
  "agent":             "research-agent",    // which agent
  "capability":        "customer.read",     // what class of action
  "action":            "read",              // which operation
  "resource":          "customer/123",      // which instance
  "origin":            "CRM-A",             // which system / trust zone
  "task":              "TASK-184",          // which unit of work
  "valid_from":        1790897735442,       // ms epoch
  "expires_at":        1790898035442,       // ms epoch
  "policy_version":    "customer-read-v4",
  "integrity_value":   "af1:sha256:<hex>"   // seal over all of the above
}
```

Canonicalization is explicit: `|`-joined `key=value` pairs over a **fixed field list**,
sorted and normalized, then SHA-256. Key order never affects the result, so a re-serialised
object cannot slip past the check.

Verified with `hmac.compare_digest`, so the comparison is not a timing oracle.

---

## The gate

Every execution traverses the same pipeline. **There is no other path to a capability.**

| # | Stage | Deny reason | Why here |
|---|---|---|---|
| 0 | Schema | `MALFORMED_REQUEST` | Nothing is interpretable yet |
| 1 | Authorization present | `MISSING_AUTHORIZATION` | Fail immediately; never default-allow |
| 2 | **Integrity** | `INTEGRITY_MISMATCH` | Detect tampering before trusting any field |
| 3 | Registries | `UNKNOWN_PRINCIPAL` / `AGENT` / `CAPABILITY` / `ORIGIN` | Explicit allow-lists |
| 4 | Validity window | `AUTHORIZATION_EXPIRED` / `NOT_YET_VALID` | Time is part of the authority |
| 5 | Policy lookup | `NO_SUCH_POLICY` | Absent rule = deny, never allow |
| 6 | **Bindings** | `*_MISMATCH` | *This* request vs *that* authorization |
| 7 | Policy effect | `POLICY_DENY` | Even a valid authorization can be refused |
| 8 | Approval | `APPROVAL_MISSING` / `APPROVAL_REJECTED` | Human authority, bound to context |
| 9 | Execute | — | Only reachable if 0–8 all passed |

### Why bindings precede policy

Stage ordering is a deliberate design choice, and it was corrected during verification.
Originally the policy effect was checked before bindings, which meant a swapped
capability reported `POLICY_DENY` — technically a denial, but **wrong and leaky**: it
tells an attacker which actions are policy-blocked, and it hides the real fault.

Binding verification now precedes both policy lookup and policy effect. The most
specific failure is reported first: the request is not the authorized request.

```
capability: customer.read  ->  customer.delete
   old:  POLICY_DENY            (generic, leaks policy posture)
   new:  CAPABILITY_MISMATCH    (precise: this request is not that authorization)
```

Fail-closed is preserved either way: both orderings deny.

---

## Evidence receipts

Every decision — allow **and** deny — emits a receipt:

```jsonc
{
  "receipt_id": "RCPT-70A77D72",
  "authorization_id": "AUTH-...", "agent": "...", "principal": "...",
  "capability": "customer.read", "action": "read",
  "resource": "customer/123", "origin": "CRM-A", "task": "TASK-184",
  "policy_version": "customer-read-v4", "policy_effect": "ALLOW",
  "approval_id": null, "approval_required": false,
  "decision": "ALLOW", "deny_reason": null,
  "execution_status": "SUCCESS", "mode": "DEMO",
  "timestamp": 1790897738000, "elapsed_ms": 1,
  "result_summary": "Northwind Traders",
  "authorization_integrity": "af1:sha256:...",
  "integrity_hash": "af1:sha256:..."
}
```

The receipt answers **who acted, what happened, why it was allowed, and what proves it**.
Its own hash is recomputable from the record, so an auditor can verify the receipt has
not been edited — no access to AgentFence required.

Denials are recorded as fully as successes. A system that only logs what it allowed
cannot answer "what was attempted."

---

## AWS vs AgentFence — an honest split

The hackathon asks which AWS services are used. Being precise matters more than
impressive: **the security claim is AgentFence's logic, not an AWS feature.**

| Concern | Owner |
|---|---|
| Compute, HTTPS surface, audit storage, logs, scoped IAM | **AWS** |
| Canonicalization, integrity, binding check, gate order, receipts | **AgentFence** |

| Service | Used for | Why |
|---|---|---|
| Lambda (Python 3.12, arm64) | Runs the gate | Tiny deterministic handler; no container cold starts |
| API Gateway | Public HTTPS | Standard REST proxy integration |
| DynamoDB | Receipt persistence | On-demand, 90-day TTL, PITR, SSE; one table, one partition key |
| CloudWatch Logs | Gate decisions | Lambda-native, explicit 14-day retention |
| IAM | Execution role | Two DynamoDB actions on one table. No `AdministratorAccess` |
| CloudFormation | The stack | Reproducible infrastructure from a 400-line template |
| S3 | *(optional)* | Only if you want a separate static host; the Lambda serves the page itself |

**Deliberately not used: Bedrock / AgentCore in the critical path.** The thesis is the
authorization binding. No service was added to the stack for marketing value, and the
demo runs with zero third-party dependencies — so there is no dependency supply chain
to attack.

### Single origin, no CORS

The Lambda serves `web/index.html` directly. One public URL serves both page and API, so
the demo has no cross-origin problem, no CloudFront distribution, and no CORS headers.
The prebuilt `function.zip` includes `web/` for exactly this reason.

---

## Failure modes considered

| Scenario | Behaviour |
|---|---|
| Attacker edits the authorization object | `INTEGRITY_MISMATCH` at stage 2 |
| Attacker re-seals with a known scheme | **Not defended** — see Limitations |
| Authorization stolen and replayed verbatim | Works *only* inside the same task, origin and window |
| Approval replayed under a different task | `TASK_CONTEXT_MISMATCH` |
| Capability check that never binds context | **This is the gap AgentFence closes** |
| Model argues itself past the gate | Impossible — the model is not in the decision path |
| Frontend tampered to allow | No client-side allow path exists |
| DynamoDB unreachable | Demo continues inline; receipt returned regardless |
| Unknown capability / origin / policy | Denied — no default-allow anywhere |

### Limitations (stated, not hidden)

1. **The integrity value is unkeyed.** It detects tampering, not a determined forger who
   knows the scheme. The fix is a keyed signature (Ed25519) or a KMS-held secret, with
   the verifier re-checking. This is the most important next step and it is small.
2. **The trust anchor is the issuer.** AgentFence proves the authorization it is handed
   is intact and contextually valid. It does not prove *who issued* it — that requires
   issuer signatures and an issuer registry, which is the production design.
3. **The capability layer is deterministic and local.** The demo resolves a fake
   customer record. Real connectors are the obvious next integration.
4. **Single-process state.** Approvals and the demo scenario live in memory. Multi-
   instance deployment needs DynamoDB for state, not just for receipts.
5. **Not a delegation model.** Child-agent delegation with attenuation is *not*
   implemented. Binding an authorization to a parent and constraining the child is the
   natural next capability, and the XACML delegation profile is prior art worth reading.

---

## Repository layout

```
agentfence/
  core.py     canonicalization, issue(), integrity, binding + validity checks
  policy.py   deterministic policy table, REQUIRE_APPROVAL, approvals
  gate.py     the ordered pipeline + receipts          <- the security boundary
  api.py      Lambda handler; serves the page and the API on one origin
web/index.html   single-page demo (renders decisions, decides nothing)
infra/template.yaml   CloudFormation stack
scripts/package.py    builds function.zip; fails loudly if content is missing
scripts/secret_scan.py credential gate for a public repo
tests/                96 tests: bypass, fail-closed, integrity, approval, receipts, API
evidence/             captured test logs, runtime evidence, coding-agent proof
```

`gate.py` is the security boundary. `api.py` and the browser are transport and
presentation.
