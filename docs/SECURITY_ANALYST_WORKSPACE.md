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
