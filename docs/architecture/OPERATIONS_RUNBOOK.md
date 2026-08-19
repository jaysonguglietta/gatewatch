# Operations runbook

## Daily analyst workflow

1. Open **Coverage** before treating the findings queue as authoritative.
2. Confirm the latest run time, coverage percentage, failed accounts, and failed
   account/Regions.
3. Open **Daily findings** and work `new`, `reopened`, overdue follow-up, and
   expiring exception queues.
4. Add a note for acknowledgement; do not use acknowledgement to suppress future
   change detection.
5. Assign follow-up with owner and due date.
6. Use accepted risk only with administrator approval, a ticket, future expiry,
   and compensating controls.
7. Create or reconcile Jira tickets for findings requiring engineering work.
8. If using the Bedrock digest or finding analysis, verify claims against cited
   evidence; do not treat model confidence as evidence completeness.

## Bedrock analyst health

Open **Administration → Integrations → Amazon Bedrock analyst** to check the
approved model, Region, versioned Guardrail, and daily usage. A `Fallback only`
state does not affect deterministic findings.

| Symptom | Check | Response |
|---|---|---|
| Every request uses fallback | Bridge status, EC2 environment, role policy, model profile access | Verify stack outputs and `bedrock:InvokeModel`; redeploy rather than adding wildcard IAM |
| Guardrail fallback | Guardrail action and malicious metadata warning | Inspect normalized evidence for prompt-like tags/names; preserve it as evidence and correct the source if appropriate |
| Schema/citation fallback | Application log error class and prompt/schema versions | Reproduce with a sanitized fixture; do not expose prompt/output in logs |
| HTTP 429 | Personal/workspace counters | Wait for UTC reset or deliberately change reviewed limits in code; do not bypass the conditional reservation |
| High latency/cost | Cache-hit rate, token totals, evidence count | Reduce requested scope; retain the compact package and output cap |

After a model, prompt, schema, or Guardrail change, invoke one confirmed,
internal, and evidence-incomplete fixture. Confirm exact verdict preservation,
valid citations, audit events, usage, fallback, and no AWS mutation path.

## Azure Data Explorer source health

Open **Administration → Data sources**, expand the ADX source, and inspect its
last test, checkpoint, connection checks, and ingestion runs.

| Symptom | Check | Response |
|---|---|---|
| Entra authentication rejected | Secret rotation, tenant ID, client ID | Edit the source, replace the secret, test, then reactivate |
| Viewer access denied | ADX database role assignment | Grant database `viewer`; never grant cluster admin to solve a read failure |
| Table or column missing | Source schema and identifier spelling | Pause, correct mapping, preview, test, reactivate |
| Source degraded after timeout/429 | ADX query health and application logs | Wait or reduce batch size; test before reactivation |
| Full 1,000-row batches every cycle | Checkpoint age and source arrival rate | Reduce schedule interval only after capacity review, or partition sources |
| Rows fetched but none normalized | Evidence type and complete-row/payload mapping | Preview sanitized rows and select the matching AWS evidence type |

Do not paste client secrets, access tokens, or raw security records into tickets.
The `adx_sync_failed` event contains counts only. A sync failure does not advance
the checkpoint, so retry is duplicate-safe.

## Collection health triage

### Partial account

1. Filter Coverage to **Needs attention**.
2. Record the account ID, failed Region count, and error code.
3. Check the account item and target items in the collection DynamoDB table.
4. Check the worker log using run ID and account ID—do not paste raw tags or
   account emails into tickets.
5. Verify StackSet instance status and role trust in the member account.
6. Verify the Region is enabled and allowed centrally.
7. Start a new run after correction; do not alter the prior manifest.

Common codes:

| Code | Likely cause | Response |
|---|---|---|
| `AccessDenied` | Member role missing, trust drift, SCP, or describe deny | Inspect StackSet, trust, SCP, permission boundary |
| `OptInRequired` | Region not enabled | Remove from allowlist or enable through account governance |
| `ThrottlingException` | API/concurrency pressure | Reduce account/Region concurrency; retry |
| `NoSuchBucket` / KMS deny | Evidence configuration drift | Validate bucket/KMS policies and retained resources |
| Lambda timeout | Extremely large account/Region or API stall | Inspect duration, reduce regional concurrency, split scope if needed |

### State machine failure

- Discovery failure means no new run can be considered complete.
- Distributed child failure should be rare because expected member errors are
  recorded as target failures. The state machine still runs finalization and
  publishes pending/running accounts as incomplete. Inspect the Step Functions
  Map Run status; never interpret that manifest as organization-wide success.
- A finalizer failure leaves shards intact. Re-invoke finalization with the run
  ID only after confirming the Map Run has stopped.

### Ingestion backlog

1. Inspect `ApproximateAgeOfOldestMessage` and DLQ depth.
2. Check Aurora/Data API throttling and ingestion Lambda concurrency.
3. Identify whether failures share an object schema/version or one source.
4. Pause the event-source mapping if continuing will amplify a parser defect.
5. Deploy the parser fix, replay a quarantined object in a non-production
   workspace, then redrive the DLQ in bounded batches.

Never delete a DLQ message before its S3 object reference, failure code, and
resolution are recorded.

## Evidence verification

For any high-impact finding or audit package:

1. locate the run and target in the manifest;
2. retrieve the exact shard key/version;
3. decompress and calculate SHA-256 over canonical JSON;
4. compare to target `checksumSha256` and object metadata;
5. verify account, Region, run ID, and observation time;
6. retain the manifest, shard reference, finding fingerprint, and decision event.

## Manual collection

```bash
STATE_MACHINE_ARN="$(aws cloudformation describe-stacks \
  --stack-name gatewatch-organization-collector \
  --query 'Stacks[0].Outputs[?OutputKey==`CollectionStateMachineArn`].OutputValue' \
  --output text)"

aws stepfunctions start-execution \
  --state-machine-arn "$STATE_MACHINE_ARN" \
  --input '{"trigger":"manual-operations"}'
```

Do not start overlapping full runs unless incident response requires it. They
increase API pressure and make freshness interpretation harder.

## Backup and recovery

- S3 evidence bucket: versioning enabled; retained on stack deletion.
- DynamoDB run state: point-in-time recovery enabled; retained.
- Aurora: deletion protection, explicit backup retention, and quarterly restore
  drills must be enabled in the final production stack.
- EFS/D1 compatibility data: transitional only; do not make it the authoritative
  production governance store.

Restore to isolated resources, validate row counts/checksums, and only then
change application endpoints. Never restore over the only surviving database.

## Security incidents

If a collector or application identity is suspected compromised:

1. disable the relevant schedule/task/event-source mapping;
2. revoke workload sessions by changing/removing role trust or task role;
3. rotate service, Jira, origin, and database credentials as applicable;
4. preserve CloudTrail, S3 versions, run manifests, application logs, and audit rows;
5. compare evidence object versions/checksums against manifests;
6. inspect source-account AssumeRole events and unexpected Describe activity;
7. redeploy from a previously signed/version-pinned release;
8. document all gaps caused by unavailable evidence.

If Bedrock output is suspected of leaking or mishandling evidence, set
`BedrockEnabled=false` through CloudFormation, preserve analysis IDs, evidence
hashes, audit events, model/prompt/schema versions, and CloudTrail InvokeModel
events, and continue with deterministic findings. Do not copy prompts or raw AWS
records into an incident ticket unless the ticket system is approved for that data.
