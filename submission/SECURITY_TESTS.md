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
| `test_recomputed_hash_without_secret_is_still_caught` | Re-sealing without the right value still fails **against an unchanged request**. NOTE: this is a binding test, NOT replay protection — an attacker who mints authorization and request consistently is invisible to this check. Real replay protection is section 9. |
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

## 9. Authorization boundary (branch `feat/authz-boundary-hardening`)

The gate decides correctly given an authorization. These tests cover whether an
authorization should exist at all, whether one principal can approve its own request,
whether a captured authorization can be replayed, and whether evidence exists *before*
the effect. All of them are new on this branch; the gate's deny-by-default posture is
unchanged and asserted structurally in `tests/test_gate_posture.py`.

### 9.1 Authenticated issuance — `tests/test_auth_boundary.py` (47 tests)

| Test | Asserts |
|---|---|
| `test_authorize_without_credential_is_401` | Anonymous issuance is `401` with **no** authorization object |
| `test_authorize_with_body_principal_but_no_credential_is_401` | Naming a principal in the body does not mint authority |
| `test_state_without_credential_is_401` / `test_expire_without_credential_is_401` | The other two issuance routes are also closed |
| `test_header_authorization_type_none_rejected` / `test_body_authorization_type_none_rejected` / `test_scheme_none_rejected` | `AuthorizationType: NONE` is refused explicitly |
| `test_claimed_principal_mismatch_refused` | Body principal ≠ credential principal → `403`, no authorization |
| `test_issued_authorization_uses_credential_principal` | The principal is derived from the credential |
| `test_aliased_principal_matches_credential` | `SVC-RESEARCH`, `svc_research`, `svc.research@corp` are one identity |
| `test_tampered_payload_rejected` / `test_wrong_secret_rejected` | Only a correctly signed credential verifies |
| `test_expired_credential_rejected` / `test_not_yet_valid_credential_rejected` | Credential lifetime is enforced |
| `test_missing_server_secret_fails_closed` | No configured secret → `503`, never "auth disabled" |
| `test_skew_never_extends_a_credential` | Skew cannot resurrect an expired credential |

### 9.2 Separation of duties — `tests/test_separation_of_duties.py` (27 tests)

| Test | Asserts |
|---|---|
| `test_self_approval_denied` | A correctly sealed self-approval → `DENY REQUESTER_CANNOT_APPROVE` at the approval stage |
| `test_self_approval_by_alias_denied[*]` (×5) | Case/separator/realm variants do not create a second person |
| `test_request_principal_cannot_dodge_the_check` | Self-asserting the request principal fails at bindings, and the duty check reads the authorization's principal |
| `test_duty_check_reads_the_authorization_principal_directly` | Unit proof of the same |
| `test_distinct_approver_allowed` / `test_another_service_principal_can_approve` | A legitimate distinct approver still succeeds |
| `test_sod_denial_does_not_consume_the_authorization` | The refusal does not burn the authorization (fixes 2 and 3 compose) |
| `test_api_refuses_self_approval` / `test_api_refuses_self_approval_by_alias` | The API refuses to mint a self-approval at all |
| `test_api_refuses_approver_not_matching_credential` | An approver identity cannot be self-asserted |
| `test_hand_forged_self_approval_still_denied_at_the_gate` | Bypassing the API does not help |

### 9.3 Single use — `tests/test_single_use.py` (29 tests)

| Test | Asserts |
|---|---|
| `test_second_use_denied` | First use ALLOW, second use `DENY AUTHORIZATION_ALREADY_CONSUMED` |
| `test_many_replays_all_denied` / `test_json_round_trip_replay_denied` | Replay of the wire form is denied |
| `test_replay_with_fresh_approval_still_denied` | A new approval does not resurrect a spent authorization |
| `test_denied_request_does_not_consume` / `test_policy_denial_does_not_consume` / `test_missing_approval_does_not_consume` | Only a permitted use spends an authorization |
| `test_capability_failure_spends_the_authorization` | A committed attempt is spent (no free retry token) |
| `test_in_memory_store_is_thread_safe` / `test_concurrent_gate_calls_only_one_allows` | Exactly one concurrent winner |
| `test_in_memory_store_documents_its_limitation` | The single-process caveat must stay in the docstring |
| `test_unavailable_store_denies` / `test_store_raising_is_a_denial_not_an_allow` | A store that cannot answer denies |
| `test_production_mode_without_store_denies` | Production with no table refuses to run |
| `test_dynamodb_conditional_failure_means_already_consumed` / `test_dynamodb_first_write_wins` | The conditional-write semantics are correct |
| `test_skew_narrows_the_window_only` / `test_negative_skew_is_clamped_and_never_widens` | Clock skew can only shorten validity |
| `test_documented_limitation_consistently_minted_authorization` | Honest: the gate cannot attribute authorship; single use still bounds the damage |

### 9.4 Pre-effect keyed receipts — `tests/test_pre_effect_receipts.py` (24 tests)

| Test | Asserts |
|---|---|
| `test_receipt_is_persisted_before_the_effect_runs` | From **inside** the capability, the sealed commitment receipt is already durable |
| `test_persist_failure_prevents_the_effect` | If the receipt cannot be persisted, the capability is never invoked |
| `test_missing_key_denies` / `test_short_key_is_treated_as_unconfigured` | No key → `DENY`, no unkeyed receipt, no effect |
| `test_capability_failure_still_leaves_pre_effect_evidence` | A failed effect still leaves the commitment receipt |
| `test_valid_chain_verifies` / `test_genesis_linkage_available` | `verify_chain` accepts an intact chain |
| `test_tampered_field_detected` | Editing a receipt breaks the self-hash |
| `test_resealed_receipt_without_the_key_is_caught` | Recomputing the public hash still fails the HMAC |
| `test_removed_receipt_detected` / `test_reordered_receipts_detected` | Dropping or reordering evidence is caught |
| `test_hmac_covers_chain_linkage` | `prev_hash` is inside the seal |
| `test_key_never_appears_in_output` | The key appears in no receipt, result or error |

### 9.5 Posture unchanged — `tests/test_gate_posture.py` (7 tests)

| Test | Asserts |
|---|---|
| `test_exactly_one_allow_exit` | Exactly one ALLOW construction in `enforce` |
| `test_allow_exit_is_the_last_decision` | It follows every DENY |
| `test_many_deny_exits_remain` | ≥15 explicit DENY exits (no catch-all collapse) |
| `test_every_stage_label_is_present` | All 13 stage labels still exist |
| `test_no_bypass_parameters_were_added` / `test_injection_parameters_default_to_safe_resolution` | No bypass surface; injection points default to config resolution |
| `test_authorization_type_none_is_not_a_default_anywhere` | No module accepts NONE without rejecting it |

---

## Reproduce every result

```bash
git clone https://github.com/frostyjay7813/AgentFence && cd AgentFence
python -m pytest tests/ -q                  # 230 passed
python scripts/secret_scan.py               # PASS: no credential patterns found
python scripts/package.py                   # rebuild function.zip
python evidence/probe_runtime.py <extracted_zip_dir>   # reproduces the table in §1
```
