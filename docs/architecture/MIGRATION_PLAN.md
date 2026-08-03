# Migration plan

## Current and target states

The legacy collector creates one organization-wide `exports/latest.json` and the
browser maps that entire snapshot. This remains useful for a personal/small
account deployment but is not the authoritative 500-account path.

The target state uses per-account/Region shards, Aurora observations, paginated
APIs, and explicit run coverage.

## Phases

### Phase 1 — dual collection

- Keep the legacy collector and web inventory endpoint running.
- Deploy the organization collector to a limited OU.
- Connect the organization manifest to the Coverage UI.
- Compare group/rule counts and attachment resolution for at least seven days.

Exit: coverage and count differences are explained; no target silently vanishes.

### Phase 2 — normalized organization evidence

- Apply the PostgreSQL schema.
- Deploy platform ingestion with the evidence bucket/key parameters.
- Validate shard idempotency, checksums, target health, and current views.
- Run CloudTrail and Config backfill into the same workspace.

Exit: every successful manifest target has processed shard lineage in Aurora.

### Phase 3 — database-backed query APIs

- Implement bounded `/api/security-groups`, `/api/findings`, `/api/accounts`, and
  `/api/runs` endpoints over non-owner database roles.
- Move finding evaluation to normalized current views.
- Preserve canonical fingerprints and human workflow records.
- Add keyset pagination for large finding inventories.

Exit: ordinary browser workflows never download the organization snapshot.

### Phase 4 — identity/runtime hardening

- Replace shared Basic Auth with OIDC and MFA.
- Enforce central permissions and immutable identity subjects.
- Separate web and bridge workloads/roles.
- Add TLS origin, WAF/rate limits, immutable images, SBOM/provenance, and signed releases.
- Enable forced PostgreSQL RLS and restore drills.

Exit: every priority-zero security acceptance criterion has independent evidence.

### Phase 5 — retire aggregate organization snapshot

- Stop organization mode in the legacy collector.
- Retain its bucket through the evidence retention window.
- Keep single-account mode for development/personal diagnostics if desired.
- Remove browser code that mutates the global demonstration inventory.

Exit: production reads only bounded database APIs and coverage manifests.

## Reconciliation checks

For each account/Region during dual running:

- group count;
- rule count by ingress/egress and IPv4/IPv6/reference/prefix-list peer;
- public ingress and public egress count;
- attachment count and resource identity;
- tag equality after normalization;
- configured internet-path classification;
- observation freshness;
- errors/exclusions.

Any difference must be classified as timing, permissions, Region scope, API
pagination, normalization, unsupported resource attribution, or a defect.

## Rollback

Each phase is additive. If a target phase fails, keep raw shards and manifests,
pause only the affected consumer, and continue the legacy read path. Do not
delete workflow history or overwrite previous evidence to make counts agree.
