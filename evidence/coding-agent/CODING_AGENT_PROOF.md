# Coding Agent Evidence — AgentFence

AgentFence was built end-to-end by a coding agent (Hermes) on 2026-10-01.

This document records **what the agent actually did**, including what it could not do.
Where a step was not performed, it says so rather than implying coverage.

---

## 1. What was built by the agent

3,371 lines across 12 files, in three commits:

```
bc8df4e  2026-10-01 16:31  policy model: authorization binding, deterministic policy,
                           execution gate + receipts
7b17d44  2026-10-01 16:41  demo workflow: Lambda API layer, single-page demo,
                           local verification server
fddab17  2026-10-01 17:32  AWS deployment: CloudFormation stack, Lambda packaging,
                           single-origin demo serving
```

| File | Lines | Role |
|---|---|---|
| `agentfence/gate.py` | 387 | The ordered execution pipeline — the security boundary |
| `agentfence/core.py` | 376 | Canonicalization, integrity, binding/validity checks |
| `agentfence/api.py` | 340 | Lambda handler; serves the page and API on one origin |
| `agentfence/policy.py` | 259 | Deterministic policy table, approvals |
| `web/index.html` | 766 | Single-page demo (renders decisions, decides nothing) |
| `tests/test_bypass.py` | 543 | Bypass / adversarial suite |
| `tests/test_api.py` | 189 | HTTP layer |
| `tests/test_demo_regression.py` | 93 | Regression tests for bugs found during verification |
| `infra/template.yaml` | 193 | CloudFormation stack |
| `scripts/*.py`, `serve.py` | 223 | Packaging, secret scan, local harness |

**96/96 tests pass.** The agent wrote, ran, and debugged them.

---

## 2. Agent actions against the real environment

The agent executed, not just generated:

| Action | Evidence |
|---|---|
| Ran the full suite repeatedly | `evidence/pytest_full.log` |
| Started the app and called the live API over HTTP | curl against `127.0.0.1:8099` |
| Ran the handler from the **extracted deployment zip** in a clean subprocess | `evidence/runtime_evidence.json` |
| Caught 2 real frontend bugs via a static page check (missing DOM id, TDZ crash) | fixed before deploy |
| Caught a broken packaging bug (Windows absolute path leaked into the zip) | fixed, regression-tested |
| Rebuilt and re-verified the artifact after every fix | `scripts/package.py` |
| Ran a credential scan on the public repo | `scripts/secret_scan.py` → 0 hits |
| Pushed a public repository | `github.com/frostyjay7813/AgentFence` |

---

## 3. Engineering decisions the agent made

Recorded because they are the substance of the work, not the typing.

1. **Gate ordering corrected, not worked around.** A capability swap originally reported
   `POLICY_DENY`. The agent recognised that as both wrong and leaky (it reveals policy
   posture to an attacker), and moved binding verification ahead of policy lookup. The
   fix changed product behaviour rather than adjusting a test.

2. **A demo bug was fixed at the model level.** The "expire" demo backdated a live
   authorization, which invalidated its integrity hash, so expiry always surfaced as
   `INTEGRITY_MISMATCH` — the `AUTHORIZATION_EXPIRED` stage was unreachable. Rather than
   changing the expected output, the agent added `/api/expire`, which issues a
   correctly-sealed, already-expired authorization. Locked in by
   `TestExpiryIsReachable`.

3. **Evidence corrected where it overstated.** An early secret-scan claim of "87 files
   scanned" was inflated by `.git` internals; the real count is 20. The agent fixed the
   documented number rather than leaving a flattering claim in place.

4. **Fail-closed audited by reading the code, not the docs.** The agent checked the real
   dispatch path and confirmed no default-allow exists at any stage. This was informed by
   a known failure elsewhere in the operator's own systems, where a substring keyword
   policy passed 6 of 9 consequential intents (including wire transfers and credential
   exfiltration) because there was no deny-by-default.

5. **No service added for marketing value.** Bedrock and AgentCore were deliberately kept
   out of the critical path; the security claim is AgentFence's logic, and the dependency
   surface is the standard library only.

6. **Scope held.** The directive warned against building a universal governance platform.
   The agent declined to add delegation, signing, or multi-tenancy, and documented them
   as limitations instead.

---

## 4. What the agent did NOT do (explicitly)

Stated plainly, because a coding-agent section that claims AWS work that never happened
would be worthless.

| Not done | Why |
|---|---|
| **Deploy to AWS** | No AWS credentials were available in the agent's environment: no `aws` CLI, no `AWS_*` environment variables, no `~/.aws`. The agent verified this, reported the blocker, and asked rather than fabricating a deployment. |
| **Connect to the AWS console** | Same cause. No AWS connection was made, so no console transcript exists. |
| **Publish to Builder Center** | Requires a live public URL, which requires deployment. Draft text is in `submission/BUILDER_CENTER.md`. |
| **Verify the live URL** | Nothing was deployed. Every verification result in this submission comes from the packaged artifact executed locally. |
| **Take a browser screenshot** | The browser required interactive consent and it was not worth blocking the build window; the page was verified by static analysis and by serving it over HTTP. |

**Therefore this submission contains no claim of a live AWS deployment.** The deployment
is operator-executed via [`AWS_DEPLOY_STEPS.md`](../AWS_DEPLOY_STEPS.md) — two console
steps, ~10 minutes — and the verification checklist in that document must be completed
before submitting.

---

## 5. Reproducing the agent's verification

```bash
git clone https://github.com/frostyjay7813/AgentFence && cd AgentFence
python -m pytest tests/ -q        # 96 passed
python scripts/package.py         # rebuild function.zip
python scripts/secret_scan.py     # PASS: 0 credential patterns
```

The commit history is the development-process record: three commits, each a working,
tested increment rather than a dump.
