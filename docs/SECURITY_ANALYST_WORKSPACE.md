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

1. Open **Findings → Daily findings**. The highest-risk finding is selected.
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
3. Review the compact queue or group findings by canonical security-group identity.
4. Inspect the selected finding's decision summary, risk factors, policy mapping,
   exact change, attached resources, and evidence confidence.
5. Follow direct AWS links to the security group, Config timeline, or CloudTrail event.
6. Record one structured outcome:
   - **Follow-up:** reason, assignee, current/future due date, note, and optional Jira ticket.
   - **Acknowledge:** reason, future review date, and explanation.
   - **Accept risk:** administrator approval, reason, ticket, future expiration,
     compensating controls, and justification.
   - **Resolve:** reason, remediation evidence, and resolution note.
7. Gatewatch auto-advances to the next item. Use the five-minute undo action when needed.

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
