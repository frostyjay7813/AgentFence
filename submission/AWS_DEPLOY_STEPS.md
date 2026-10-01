# AgentFence — AWS Console Deployment (exact steps)

Repo: **https://github.com/frostyjay7813/AgentFence**
Region used in examples: **us-east-1** (pick any region you have enabled)

Expected total time: **~15 minutes**. Do the steps **in order** — Step 1 must
come first because Step 2's API Gateway needs the Lambda ARN.

---

## STEP 1 — Create the Lambda function

The function must exist **before** the stack, because API Gateway integrates with it by ARN.

**Lambda → Create function**

| Field | Value |
|---|---|
| Function name | `agentfence-api` |
| Runtime | **Python 3.12** |
| Architecture | **arm64 (Graviton)** |
| Permissions | **Create a new role with basic Lambda permissions** |

Then:

1. **Configuration → General configuration → Edit**
   - **Timeout: 15 seconds**
   - **Memory: 512 MB**
   - Click **Save**

2. **Code → Deploy new code**
   - Source code: **Edit code in Lambda**
   - Delete the default `lambda_function` stub.
   - Click the orange **"Add folder"** button (or drag files in) and upload the whole
     `agentfence/` folder from the repo so it lands at the function root:
     ```
     agentfence/
       __init__.py
       api.py        <- handler
       core.py
       gate.py
       policy.py
     ```
     **Important:** Lambda's inline editor does not support nested folders well. If
     "Add folder" is awkward, use the **preferred method below** instead.
   - Set **Handler** to `agentfence.api.lambda_handler`
   - Click **Deploy**

### Preferred alternative (avoids the inline editor entirely)

If you have the AWS CLI or CodeShell available, this is more reliable:

```bash
# from a clone of the repo
cd AgentFence
zip -r function.zip agentfence
aws lambda update-function-code \
  --function-name agentfence-api \
  --zip-file fileb://function.zip \
  --publish
```

**Then copy the function ARN** — you need it for Step 2. It looks like:
```
arn:aws:lambda:us-east-1:123456789012:function:agentfence-api
```

3. **Configuration → Environment variables → Edit**, add:
   - `AGENTFENCE_MODE` = `DEMO`
   - Save.

---

## STEP 2 — Deploy the infrastructure stack

**CloudFormation → Stacks → Create stack → Upload template**

1. **Template**: upload `infra/template.yaml` from the repo
2. Click **Next**
3. **Stack name**: `agentfence`
4. **Parameters** — set these:

| Parameter | Value |
|---|---|
| `Project` | `agentfence` (default is fine) |
| `LogRetention` | `14` (default) |
| `FuncArn` | **paste the Lambda ARN from Step 1** |

5. Click **Next → Create**
6. Wait for `CREATE_COMPLETE` (1–2 minutes)
7. Open the **Outputs** tab and record:
   - **`ApiUrl`** → this is your API base URL, e.g.
     `https://abc123.execute-api.us-east-1.amazonaws.com/prod`

---

## STEP 3 — Upload the demo front-end to S3

1. **S3 → Buckets → `agentfence-site-<accountid>-us-east-1`**
2. Delete the pre-created placeholder objects if any.
3. Click **Upload → Upload files** and upload **`web/index.html`** to the bucket root.

### Give it a real public HTTPS URL (recommended)

The S3 bucket itself is not web-addressable until you enable static hosting.

1. In the bucket → **Properties → Static website hosting → Edit**
2. **Static website hosting: Enable**
3. Index document: `index.html`, Error document: `index.html`
4. Save. You'll get a URL like:
   ```
   http://agentfence-site-123456789012.s3-website-us-east-1.amazonaws.com/index.html
   ```

> **This URL is HTTP-only.** For a judge-facing **HTTPS** link, either:
> - Open the bucket's **Properties → Static website hosting** and use the
>   **CloudFront** distribution you create in Step 4, or
> - In the console choose **Properties → Static website → Edit** and then use the
>   **"Open website"** button, which gives the working (HTTP) URL while you set up
>   CloudFront for the final HTTPS link.

---

## STEP 4 — Front it with CloudFront (HTTPS)

1. **CloudFront → Create distribution**
2. **Origin**: choose **S3** → select the `agentfence-site-...` bucket
   > If using the website endpoint (recommended, because the API is on a different
   > origin anyway), set **Origin path** empty and **Origin protocol** to **HTTP only**.
3. **Viewer protocol policy**: **Redirect HTTP to HTTPS**
4. **Allowed methods**: GET, HEAD, OPTIONS
5. Do **not** enable Origin Access Control if you are using the public website
   endpoint. (If you later lock the bucket down with OAC, re-upload the page.)
6. **Create and wait for Deployed**, then copy the **domain name**:
   ```
   https://d1234abcd.cloudfront.net
   ```

---

## STEP 5 — Point the demo at the live API

The page currently calls the API **same-origin** (`API = ""`). Since the page is
served from CloudFront/S3 and the API is on API Gateway, set the API base URL:

1. Edit `web/index.html` in the repo, find near the bottom of the `<script>` block:
   ```js
   const API = "";
   ```
   change to:
   ```js
   const API = "https://abc123.execute-api.us-east-1.amazonaws.com/prod";
   ```
2. Commit and push, then **re-upload `index.html` to S3**.

> **CORS note:** the Lambda returns `Content-Type: application/json` and no CORS
> headers, so a cross-origin call from the CloudFront page will be blocked by the
> browser. Two clean options:
> - **(A) Fastest — skip CloudFront for the page.** Use the S3 website URL and add
>   the API Gateway URL as a query param the page reads. *I can patch the page to
>   accept `?api=` so no rebuild is needed.*
> - **(B) Correct — serve the page from the same API.** Add the static HTML as the
>   Lambda response for `GET /` so there is one origin and no CORS at all. This is the
>   cleanest single-URL demo. *I can implement this in ~10 lines.*

**Recommended: option B.** One public HTTPS URL for both page and API is a much
better judge experience. Tell me and I'll add it.

---

## STEP 6 — Verify before you submit (the live gate)

Run every one of these from a **clean browser / incognito window**:

| # | Check | Expected |
|---|---|---|
| 1 | Open the public HTTPS URL | Landing page renders |
| 2 | Click **Launch Interactive Demo** | Demo loads, shows `TASK-184` / `research-agent` / `customer.read` |
| 3 | `/health` on the API URL | `{"status":"ok","gate":"fail-closed"}` |
| 4 | Click **Execute valid action** | `EXECUTION ALLOWED`, record returned, receipt appears |
| 5 | Click **Change resource** | `EXECUTION DENIED · RESOURCE_MISMATCH` |
| 6 | Click **Change action** | `EXECUTION DENIED · CAPABILITY_MISMATCH` |
| 7 | Click **Change origin** | `EXECUTION DENIED · ORIGIN_MISMATCH` |
| 8 | Click **Replay task** | `EXECUTION DENIED · TASK_CONTEXT_MISMATCH` |
| 9 | Click **Expire authorization** | `EXECUTION DENIED · AUTHORIZATION_EXPIRED` |
| 10 | Click **Refresh audit trail** | Receipt rows appear with `DEMO` mode label |
| 11 | Click **Run approval flow** | `APPROVAL_MISSING` → then `ALLOW` with approval ID |

If step 5–8 show anything other than DENY, **do not submit** — tell me and I will fix it.

---

## STEP 7 — Capture the coding-agent evidence

The hackathon requires proof a coding agent was connected to the AWS console.

The most credible artifact: **this Hermes agent built AgentFence end-to-end**
(policy engine, gate, tests, front-end, CloudFormation), and you deploy it with an
AWS-connected coding agent or the console. To satisfy this cleanly:

1. Use an AWS-connected coding agent (Claude Code with the AgentCore toolkit, Amazon
   Q Developer CLI, or Kiro) to deploy the stack from this repo, **or**
2. Have your coding agent perform the console steps above and capture the session log.

Save the transcript into `evidence/coding-agent/` with secrets redacted. I have
already scaffolded `evidence/coding-agent/CODING_AGENT_PROOF.md` for this.

---

## Least privilege (what you are deploying)

Verify in **IAM → Roles → agentfence** after deploying. The execution role should have
exactly two DynamoDB actions scoped to one table:

```
dynamodb:PutItem   arn:aws:dynamodb:us-east-1:<account>:table/agentfence-audit
dynamodb:Scan      arn:aws:dynamodb:us-east-1:<account>:table/agentfence-audit
```

plus CloudWatch Logs writes. There should be **no `AdministratorAccess`** anywhere.
The audit template (`submission/SECURITY_TESTS.md`) records this check.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Stack fails on `FuncArn` | You skipped Step 1, or pasted the function **name** instead of its **ARN** |
| API returns `{"error":"NOT_FOUND"}` | The `ApiUrl` needs the `/prod` suffix (it's in the Outputs tab) |
| Page loads but demo buttons do nothing | Cross-origin CORS — use Step 5 option B |
| Lambda 500s with `ModuleNotFoundError` | The `agentfence/` folder is not at the function root; use the zip upload method |
| `SignatureDoesNotMatch` | Nothing to do with AgentFence — it's the AWS CLI call. Use console upload instead |
