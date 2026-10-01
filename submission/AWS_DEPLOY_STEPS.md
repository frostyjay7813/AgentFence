# AgentFence — AWS Deployment (exact console steps)

Repo: **https://github.com/frostyjay7813/AgentFence**
Time: **~10 minutes.** Two steps, in order.

> **The Lambda serves the demo page itself.** You do **not** need S3, CloudFront, a
> custom domain, or any CORS configuration. One API Gateway URL is the whole app.

---

## STEP 1 — Create the Lambda function from the prebuilt package

The file **`function.zip`** is in the repo root and is the exact deployment artifact.
It is already verified — it was tested from the extracted archive, not just the source tree.

**Lambda → Create function**

| Field | Value |
|---|---|
| Function name | `agentfence-api` |
| Runtime | **Python 3.12** |
| Architecture | **arm64 (Graviton)** |
| Permissions | **Create a new role with basic Lambda permissions** |

Then:

1. **Configuration → General configuration → Edit** → **Timeout: 15 seconds**, **Memory: 512 MB** → **Save**
2. **Code tab → Upload a .zip file → Upload** → choose `function.zip` → **Save**

> If you cloned the repo instead, regenerate it with:
> ```bash
> python scripts/package.py     # prints the file list and verifies contents
> ```

3. **Copy the function ARN** (top-right of the Code tab). It looks like:
   ```
   arn:aws:lambda:us-east-1:123456789012:function:agentfence-api
   ```

4. **Configuration → Environment variables → Edit** → add:
   - `AGENTFENCE_MODE` = `DEMO`
   - **Save**

---

## STEP 2 — Deploy the stack (API Gateway + DynamoDB + scoped IAM)

**CloudFormation → Stacks → Create stack → Upload template**

1. Upload **`infra/template.yaml`** → **Next**
2. **Stack name**: `agentfence`
3. **Parameters**:

| Parameter | Value |
|---|---|
| `Project` | `agentfence` |
| `LogRetention` | `14` |
| `FuncArn` | **the ARN you copied in Step 1** |

4. **Next → Create** → wait for `CREATE_COMPLETE` (1–2 min)
5. Open the **Outputs** tab. Copy **`ApiUrl`**, e.g.:
   ```
   https://abc123def4.execute-api.us-east-1.amazonaws.com/prod
   ```

**That URL is the submission.** Append nothing. It serves both the page and the API.

---

## STEP 3 — Wire persistence (30 seconds, recommended)

The Lambda already has read/write permission to the audit table, but the table name is
not yet in the function's environment. To make the **Audit** tab persist to DynamoDB:

1. **Lambda → agentfence-api → Configuration → Environment variables → Edit**
2. Add: `AGENTFENCE_AUDIT_TABLE` = `agentfence-audit` → **Save**

**Skip this and the demo still works perfectly** — receipts are returned inline and
shown in the Audit tab; only the cross-session history is lost.

---

## STEP 4 — Verify the live gate (do this from a clean/incognito window)

This is the pass/fail check. Work down the list.

| # | Action | Expected result |
|---|---|---|
| 1 | Open the `ApiUrl` in a clean browser | Landing page renders, headline "Authorization that follows the action." |
| 2 | Click **Launch Interactive Demo** | Shows `TASK-184` · `research-agent` · `customer.read` |
| 3 | Open `<ApiUrl>/health` | `{"status":"ok","gate":"fail-closed",...}` |
| 4 | **Execute valid action** | `EXECUTION ALLOWED` + "Northwind Traders" + a receipt |
| 5 | **Change resource** | `EXECUTION DENIED` · `RESOURCE_MISMATCH` |
| 6 | **Change action** | `EXECUTION DENIED` · `CAPABILITY_MISMATCH` |
| 7 | **Change origin** | `EXECUTION DENIED` · `ORIGIN_MISMATCH` (shows expected vs received) |
| 8 | **Replay task** | `EXECUTION DENIED` · `TASK_CONTEXT_MISMATCH` |
| 9 | **Expire authorization** | `EXECUTION DENIED` · `AUTHORIZATION_EXPIRED` |
| 10 | **Tamper integrity** | `EXECUTION DENIED` · `INTEGRITY_MISMATCH` |
| 11 | **Refresh audit trail** | Receipt rows appear, each labelled `DEMO` |
| 12 | **Run approval flow** | `APPROVAL_MISSING` → then `ALLOW` with an approval ID |
| 13 | **Replay the approval under TASK-185** | `APPROVAL REJECTED` |

**If steps 5–10 show anything other than DENY, do not submit — tell me and I will fix it.**

---

## STEP 5 — Least-privilege check (do this, it is part of the evidence)

**IAM → Roles → `agentfence`** and confirm the role contains **only**:

```
dynamodb:PutItem   arn:aws:dynamodb:<region>:<account>:table/agentfence-audit
dynamodb:Scan      arn:aws:dynamodb:<region>:<account>:table/agentfence-audit
logs:CreateLogGroup / CreateLogStream / PutLogEvents   (log-group:/aws/lambda/agentfence-*)
```

There must be **no `AdministratorAccess`** and no wildcard resource. Paste what you see
into `submission/SECURITY_TESTS.md`.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Page loads but buttons do nothing | Open the **browser console**. If you see a CORS error, you are loading the page from S3/CloudFront instead of from the `ApiUrl` — use the `ApiUrl` only. |
| `{"error":"NOT_FOUND"}` | You dropped the `/prod` suffix. Use the exact `ApiUrl` from Outputs. |
| `ModuleNotFoundError: agentfence` | The zip layout is wrong. Use the prebuilt `function.zip`; do not zip the folder itself (you'd get `agentfence/agentfence/...`). Verify with `unzip -l function.zip`. |
| `Internal server error` on `/health` | Check **CloudWatch → Log Groups → `/aws/lambda/agentfence-api`** for the traceback. |
| Stack fails: "Value of property FuncArn is invalid" | You pasted the function **name** instead of the **ARN**. It must start `arn:aws:lambda:`. |
| `CAPABILITY_MISMATCH` fires on the valid action | You edited `web/index.html` inside the zip and broke the scenario fields. Re-upload the pristine `function.zip`. |

---

## What is deployed (for your architecture section)

**AWS infrastructure:** Lambda (Python 3.12, arm64) · API Gateway (REST, proxy) · DynamoDB
(on-demand, 90-day TTL, PITR, SSE) · CloudWatch Logs (14-day retention) · IAM (scoped
execution role) · CloudFormation.

**AgentFence application logic** (none of this is an AWS feature): canonicalization ·
SHA-256 integrity values · the binding check · the deterministic policy table ·
approval binding · the ten-stage gate ordering · evidence receipts.

Deliberately **not** used: Bedrock / AgentCore in the critical path. The thesis is the
authorization binding, which is AgentFence logic. A service was not added to the stack
for marketing value.
