# AgentFence — Security Test Evidence

All results below are **observed output**, not design intent. Raw logs:
[`evidence/pytest_full.log`](../evidence/pytest_full.log) and
[`evidence/runtime_evidence.json`](../evidence/runtime_evidence.json).

```
$ python -m pytest tests/ -q
96 passed in 0.51s
```

The runtime evidence was captured from the **extracted `function.zip`** — the same
artifact uploaded to Lambda — executed in a clean subprocess, not from the dev tree.

---

## 1. The core invariant

**Valid context executes; every substitution is denied with a specific reason.**

| Case | Decision | Reason | Gate stage |
|---|---|---|---|
| Authorized context | **ALLOW** | — | `10-execute` |
| Resource `customer/123` → `customer/999` | **DENY** | `RESOURCE_MISMATCH` | `5-bindings` |
| Capability `customer.read` → `customer.delete` | **DENY** | `CAPABILITY_MISMATCH` | `5-bindings` |
| Action `read` → `delete` | **DENY** | `ACTION_MISMATCH` | `5-bindings` |
| Origin `CRM-A` → `CRM-B` | **DENY** | `ORIGIN_MISMATCH` | `5-bindings` |
| Task `TASK-184` → `TASK-185` | **DENY** | `TASK_CONTEXT_MISMATCH` | `5-bindings` |
| Agent `research-agent` → `support-agent` | **DENY** | `AGENT_MISMATCH` | `5-bindings` |
| Validity window already closed | **DENY** | `AUTHORIZATION_EXPIRED` | `4-validity` |
| Authorization field tampered post-issuance | **DENY** | `INTEGRITY_MISMATCH` | `2-integrity` |
| No authorization presented | **DENY** | `MISSING_AUTHORIZATION` | `1-authorization` |

Valid execution returned: `ALLOW` / `SUCCESS` / record `Northwind Traders`, receipt
`RCPT-70A77D72`, with a recomputable `af1:sha256:` evidence hash.

---

## 2. Fail-closed behaviour (no default allow)

| Test | Asserts |
|---|---|
| `test_missing_request_field[*]` (×7) | Each of the 7 required fields absent → DENY |
| `test_empty_request_field[*]` (×7) | Each present-but-empty → DENY |
| `test_unknown_capability_no_default_allow` | Unknown capability → DENY |
| `test_unknown_agent` / `test_unknown_origin` | Unregistered identity/origin → DENY |
| `test_no_such_policy_fails_closed` | No policy rule exists → DENY |
| `test_missing_authorization` | No auth → DENY |
| `test_denial_never_falls_back_to_broader_auth` | A denial never silently widens |
| `test_unknown_resource_outside_prefix` | Resource outside the authorized prefix → DENY |
| `test_gate_has_no_bypass_flag` | No hidden allow-all flag in the gate |
| `test_delete_capability_unreachable_by_policy` | Denied capability unreachable even with a valid authorization |
| `test_policy_deny_is_absolute` | A valid authorization cannot override a DENY policy |
| `test_authorization_cannot_be_issued_with_wildcards` | `*` rejected as principal/agent/capability/origin/task |

**There is no permissive fallback anywhere in the gate.** Every failure path returns a
stable machine-readable reason (`test_every_deny_path_has_stable_reason`).

> This is the specific discipline AIF's own policy layer failed: a substring keyword
> match with no deny-by-default passed 6 of 9 consequential intents in its own probe,
> including wiring money from a production account and exfiltrating credentials.
> AgentFence's registries and policy lookup are explicit allow-lists, not patterns.

---

## 3. Integrity

| Test | Asserts |
|---|---|
| `test_tampered_field_detected[*]` (×9) | Tampering any bound field, the expiry, or the policy version is detected |
| `test_stripped_integrity_value_detected` | Removing the hash entirely → DENY |
| `test_recomputed_hash_without_secret_is_still_caught` | Re-sealing without the right value still fails |
| `test_tampered_numeric_field_detected_by_integrity` | Numeric fields are covered too |
| `test_integrity_is_order_independent` | Hash covers values, not key order |
| `test_receipt_integrity_detects_tampering` | Receipts are also tamper-evident |

Integrity uses SHA-256 over a canonicalized field set, compared with
`hmac.compare_digest`. In this build the integrity value is **unkeyed and therefore an
integrity check, not a signature** — it detects accidental or naive tampering, not a
forged re-seal by someone who knows the scheme. Keyed signing is the documented next
step (see [`ARCHITECTURE.md`](ARCHITECTURE.md#limitations)).

---

## 4. Approval binding

| Test | Asserts |
|---|---|
| `test_approval_required_without_approval` | `REQUIRE_APPROVAL` capability without approval → `APPROVAL_MISSING` |
| `test_valid_approval_allows` | Matching approval → ALLOW, approval ID recorded in the receipt |
| `test_fake_approval_rejected` | Invented approval → DENY |
| `test_approval_for_other_authorization_rejected` | Approval from another authorization → DENY |
| `test_approval_does_not_survive_context_change[*]` | Changing resource, origin, or task after approval invalidates it |
| `test_expired_approval_rejected` | Expired approval → DENY |
| `test_approval_does_not_transfer_to_other_task` (API) | Replaying an approval under `TASK-185` → `TASK_CONTEXT_MISMATCH` |

Observed end-to-end:
```
1) no approval        -> DENY  APPROVAL_MISSING       (approval_required: true)
2) human approves      -> APPR-40599408 by human.jay
3) with approval       -> ALLOW SUCCESS
4) replay under TASK-185 -> DENY TASK_CONTEXT_MISMATCH
```

---

## 5. Least privilege in the deployed infrastructure

`infra/template.yaml` grants the Lambda execution role **only**:

```
dynamodb:PutItem   arn:aws:dynamodb:<region>:<account>:table/agentfence-audit
dynamodb:Scan      arn:aws:dynamodb:<region>:<account>:table/agentfence-audit
logs:CreateLogGroup / CreateLogStream / PutLogEvents
```

No `AdministratorAccess`, no wildcard resource. The only `Principal: "*"` in the
template is the S3 bucket policy for public read of the demo page.

*Operator action:* after deploying, paste the actual role JSON into
`evidence/iam-role.json` (see [`AWS_DEPLOY_STEPS.md`](AWS_DEPLOY_STEPS.md) Step 5).

Additional posture in the template: DynamoDB on-demand, 90-day TTL, point-in-time
recovery, SSE enabled; CloudWatch log retention 14 days; S3 versioning + SSE + full
public-access block; no third-party runtime dependencies.

---

## 6. Secret scan

```
$ python scripts/secret_scan.py
files scanned: 20
credential-pattern hits: 0

PASS: no credential patterns found.
```

(20 text files in the repo; `function.zip` and other binaries are excluded, and
`.git` internals are not scanned. The scan is part of the repo, not a one-off.)

Patterns: AWS access-key IDs, secret access keys, private-key headers, Slack tokens,
GitHub tokens, and provider API keys. The repository contains **no credentials**, and
the application ships no secrets to the browser — `/health` has an explicit test
(`test_health_leaks_no_secrets`).

---

## 7. Demo cannot lie

The browser has **no client-side allow path**. Every result on screen is the literal
JSON response from the server-side gate. The offline fallback is explicitly labelled
`LOCAL` in the UI and in every receipt (`mode: "DEMO"` / `test_demo_mode_labeled_never_blurred`)
so a judge can never mistake a local result for a server result.

---

## 8. Bugs found and fixed during verification

Recorded because the fixes changed observed behaviour:

1. **Gate ordering.** The policy effect was evaluated before bindings, so a capability
   swap reported `POLICY_DENY` instead of `CAPABILITY_MISMATCH`. Reordered so bindings
   precede both policy lookup and policy effect. (Design fix, not a test relaxation.)
2. **Expiry was unreachable.** The demo backdated a live authorization, which broke its
   integrity value, so expiry surfaced as `INTEGRITY_MISMATCH`. Added `/api/expire`,
   which issues a correctly-sealed, already-expired authorization. Locked in by
   `TestExpiryIsReachable`.
3. **Approval flow was misleading.** Reusing the read authorization for the write
   approval reported `CAPABILITY_MISMATCH`. Locked in by `TestApprovalFlowIsReachable`.
4. **Broken packaging.** A Windows absolute path leaked into the zip via
   `requirements.txt`. Zero runtime dependencies, so it is no longer shipped.
5. **Frontend.** A missing DOM id (`apBanner`) and a temporal-dead-zone crash on
   `LOCAL_RECEIPTS` were caught by a static page check before deployment.

---

## Reproduce every result

```bash
git clone https://github.com/frostyjay7813/AgentFence && cd AgentFence
python -m pytest tests/ -q                  # 96 passed
python scripts/package.py                   # rebuild function.zip
python evidence/probe_runtime.py <extracted_zip_dir>   # reproduces the table in §1
```
