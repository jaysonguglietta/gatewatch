# Security analyst workspace

## Purpose

The daily findings workspace is designed for a small security team reviewing
security-group exposure across hundreds of AWS accounts. It prioritizes fast,
defensible decisions over dashboard browsing.

## Information architecture

Gatewatch exposes five primary workspaces:

1. **Findings** — daily review, broad access, exposure intelligence, drift, and recommendations.
2. **Inventory** — access explorer, path evidence, connectivity history, and organization coverage.
3. **Governance** — applications, owners, policies, review campaigns, and remediation.
4. **Reports** — detailed reports, CloudTrail imports, and AWS handoffs.
5. **Administration** — data sources, S3 ingestion, Jira, access, retention, and audit configuration.

The expanded secondary navigation changes with the selected workspace, keeping
all existing capabilities without presenting nineteen equal-priority choices.

## Daily workflow

1. Open **Findings → Daily findings**. Begin with the **Fix First** security group.
   Gatewatch ranks one consolidated work item per canonical security-group ARN,
   using effective exposure, attached-asset criticality, risk, traffic,
   recurrence, change recency, and approval provenance. The three lanes are:

   - **Confirmed internet:** the public path is supported end to end.
   - **Evidence incomplete:** a broad rule exists, but decisive route,
     attachment, analyzer, or coverage evidence is missing.
   - **Internal risk:** no public path is confirmed, while lateral or
     least-privilege risk may remain.

   Use a guided hunt for common high-value patterns or **Describe a hunt** to
   generate a visible structured expression. The preview is always editable;
   unsupported natural-language concepts are not silently guessed.
2. Choose a personal/team saved view or narrow organization, OU, account, Region,
   owner, environment, status, severity, or effective internet exposure. Internet,
   no-internet, and incomplete-evidence findings remain separate filter states.
   The search box supports free text and field-aware clauses. Clauses are ANDed,
   quoted values preserve spaces, and the full canonical security-group ARN is
   searchable. For example:

   ```text
   account:123456789012 ingress:"TCP/443" source:0.0.0.0/0 risk:>=70
   ```

   Identity and scope fields are `arn:`, `sg:`/`id:`, `name:`, `account:`/`acct:`,
   `region:`, `vpc:`, `ou:`, `app:`, and `env:`. Rule fields are `ingress:`,
   `egress:`, `rule:`, `port:`, `protocol:`, and `source:`. Analysts can also use
   `severity:`, `risk:`, `verdict:`, `status:`, `owner:`, `assignee:`, `policy:`,
   `path:`, `resource:`, `tag:`, `actor:`, `evidence:`, `confidence:`, and `age:`.
   Intent and evidence-specific fields are `intent:`, `ticket:`, `approved:`,
   `flows:`, `coverage:`, `rule-id:`, and `criticality:`.
   Numeric fields support exact values, ranges, and comparisons such as
   `risk:70-90`, `confidence:>=70`, and `age:>30`. Search is retained in the URL
   and in saved personal or team views. Unsupported fields and unclosed quotes are
   reported inline rather than treated as successful empty-result searches.

   Boolean expressions support `AND`, `OR`, `NOT`, and parentheses, with `NOT`
   evaluated before `AND`, and `AND` before `OR`. Queries are bounded to 500
   characters, 40 clauses, and five nested groups. History-aware fields include
   `changed-after:`, `changed-before:`, `changed-by:`, and `recurrence:`. Example:

   ```text
   (port:22 OR port:3389) AND internet:confirmed NOT status:accepted-risk
   ```

   Analysts can use the visual query builder or field/value autocomplete instead
   of typing syntax. Result intelligence recalculates account, Region, severity,
   internet, owner, and rule-direction facets for the complete matching set. Each
   queue item explains which positive clauses matched; excluded terms are never
   presented as supporting evidence.

   Switch the search scope to **Findings + AWS evidence** to include bounded,
   normalized Config, CloudTrail, Flow Log, network-analysis, service-access, and
   managed-finding records. Raw records remain in the evidence ledger; only safe
   normalized metadata is returned in the search result cards.

   **Monitor search** creates a durable hourly, daily, or weekly evidence monitor
   using the same query and filters. **Export all results** exports the complete
   server-filtered result set with the query recorded as lineage. Page selection
   can expand to all results only when the set contains at most 100 findings;
   accepted-risk and Jira actions retain their 20-finding limits. The API
   revalidates every fingerprint, permission, evidence gate, and decision field.
3. Review the grouped queue. Its five-step truth strip shows **effective rule →
   entry point → network path → observed traffic → exposure verdict**. Expand a
   group only when the contributing signal matters; otherwise work at the
   security-group level to avoid duplicate remediation.
4. Use the investigation tabs:

   - **Summary:** decision context, explainable risk, intent, and exact change.
   - **Exposure path:** decisive path evidence and the missing-evidence checklist.
   - **Impact:** attached resources, public/private addresses, criticality, and tags.
   - **Remediation:** current/proposed access, blast radius, reviewable CLI,
     CloudFormation and Terraform guidance, plus post-change checks.
   - **Notes & history:** append-only workflow decisions.
   - **Raw evidence:** preserved normalized snapshot, lineage, and limitations.
5. Follow direct AWS links to the security group, Config timeline, or CloudTrail event.
6. Record one structured outcome:
   - **Follow-up:** reason, assignee, current/future due date, note, and optional Jira ticket.
   - **Acknowledge:** reason, future review date, and explanation.
   - **Accept risk:** administrator approval, reason, ticket, future expiration,
     compensating controls, and justification.
   - **Resolve:** reason, remediation evidence, and resolution note.
7. Gatewatch auto-advances to the next item. Use the five-minute undo action when needed.

## Evidence interpretation

- A `0.0.0.0/0` or `::/0` rule is a candidate exposure, not sufficient proof of
  internet reachability. Gatewatch also evaluates public entry points, public
  addresses, subnet routes, internet gateways, NACLs, and analyzer evidence.
- A VPC Flow Log ACCEPT observation increases urgency and confirms use. No
  matching flow does not prove safety: the path may be unused, the time window
  may be incomplete, or Flow Logs may be absent.
- Terminal decisions remain blocked when required evidence is stale, inferred,
  or incomplete. Follow-up is available to assign evidence collection.
- Remediation code is an analyst-reviewed package. Gatewatch does not silently
  execute the generated AWS CLI, CloudFormation, or Terraform change.

## Reviewing CloudFormation and Terraform

Open **Recommendations → IaC guardrails** and upload up to 40 files per browser
session. Supported inputs are CloudFormation `.yaml`, `.yml`, `.template`, and
JSON, plus Terraform `.tf` and `.tf.json`. Each file is limited to 5 MB and the
selected batch to 50 MB.

Gatewatch recognizes CloudFormation security groups and standalone ingress or
egress resources, Terraform `aws_security_group`, legacy
`aws_security_group_rule`, and modern `aws_vpc_security_group_ingress_rule` or
`aws_vpc_security_group_egress_rule` resources. Rules from separate files are
consolidated by logical resource address.

The review reports:

- unrestricted IPv4 and IPv6 ingress;
- public SSH, RDP, database, cache, search, development, and management ports;
- all-protocol access, wide port ranges, very broad private CIDRs, and open egress;
- missing rule descriptions and unresolved deployment-time expressions;
- internet-gateway, default-route, and public-attachment signals;
- exact source file, resource address, and line where available.

Static IaC evidence produces **potential internet path**, **public reachability
unresolved**, or **no public ingress identified**. It never claims that an
undeployed service is reachable. CloudFormation transforms and nested stacks,
Terraform modules, dynamic blocks, provider plugins, external data sources, and
computed values are not executed. Their unresolved effects must be supplied as
resolved CI plan evidence or verified after deployment.

Files remain in the browser session and are not sent to the Gatewatch server.
Use the sample files under `samples/iac-review/` to test the workflow safely.

## Keyboard controls

| Key | Action |
| --- | --- |
| `J` | Next finding |
| `K` | Previous finding |
| `F` | Create follow-up |
| `A` | Acknowledge |
| `E` | Accept risk |
| `R` | Resolve |
| `Esc` | Close the detail pane |
| `?` | Show the shortcut reminder |

Shortcuts do not fire while focus is inside an input, select, textarea, modal,
or editable control.

## Decision safety

- Follow-up is always available so evidence gaps can be assigned and tracked.
- Acknowledge, accepted risk, and resolution require observed evidence with at
  least 70% confidence. Live AWS evidence must also be complete and no more than
  24 hours old.
- The API repeats every evidence, permission, size, and date check. Disabled UI
  controls are not treated as authorization.
- Accepted-risk batches are limited to 20 findings; all other bulk changes are
  limited to 100 stable fingerprints.
- Decisions store an evidence snapshot, authenticated actor, structured reason,
  notes, ownership, dates, and compensating controls in append-only history.
- Expired accepted risk appears reopened. A future observation also reopens a
  resolved finding while preserving its prior history.
- Undo uses a short-lived, actor-bound server snapshot. The client supplies only
  the opaque token and cannot choose the state being restored.

## Personalization and collaboration

Queue density and visible metadata fields are non-sensitive device preferences
stored in browser local storage. Findings, notes, decisions, saved views, and
review history remain server persisted.

Saved views can be personal or shared with the security team. Only the owner can
delete a saved view, and a team view cannot become another user's default.

## Responsive behavior

On desktop the queue and evidence pane remain visible together. On narrow
screens they stack vertically: the queue occupies the upper viewport and the
selected evidence pane appears below it. All triage controls keep keyboard focus
states and native form labels.

## AWS production mapping

The Sites/D1 runtime uses additive companion tables to avoid unsafe live table
alterations. The Aurora production model stores the same structured decision
fields directly on workflow and event rows, plus team view visibility and
short-lived undo snapshots. This keeps the UI contract stable when the web tier
moves fully to AWS.
