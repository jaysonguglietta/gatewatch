import { env } from "cloudflare:workers";

type FreshnessSource = {
  id: string;
  name: string;
  freshnessSlaMinutes: number;
  freshnessStatus: "unknown" | "healthy" | "warning" | "breached";
  lastSuccessfulObjectAt: string;
  updatedAt: string;
};

export type FreshnessEvaluation = {
  checked: number;
  breached: number;
  transitions: Array<{
    sourceId: string;
    sourceName: string;
    from: FreshnessSource["freshnessStatus"];
    to: FreshnessSource["freshnessStatus"];
    lagMinutes: number;
    slaMinutes: number;
  }>;
};

function freshnessState(source: FreshnessSource, now: number) {
  const observed = Date.parse(source.lastSuccessfulObjectAt);
  const hasCheckpoint = Number.isFinite(observed);
  const baseline = hasCheckpoint ? observed : Date.parse(source.updatedAt);
  if (!Number.isFinite(baseline)) {
    return { status: "unknown" as const, lagMinutes: 0 };
  }
  const lagMinutes = Math.max(0, Math.floor((now - baseline) / 60_000));
  if (lagMinutes > source.freshnessSlaMinutes) return { status: "breached" as const, lagMinutes };
  if (lagMinutes >= Math.floor(source.freshnessSlaMinutes * 0.8)) return { status: "warning" as const, lagMinutes };
  return { status: hasCheckpoint ? "healthy" as const : "unknown" as const, lagMinutes };
}

export async function evaluateAdxFreshness(): Promise<FreshnessEvaluation> {
  const rows = await env.DB.prepare(
    `SELECT id, name, freshness_sla_minutes AS freshnessSlaMinutes,
            freshness_status AS freshnessStatus,
            last_successful_object_at AS lastSuccessfulObjectAt,
            updated_at AS updatedAt
     FROM ingestion_sources
     WHERE workspace_id = 'default' AND provider = 'azure-data-explorer'
       AND status IN ('live', 'degraded')
     ORDER BY id LIMIT 5000`,
  ).all<FreshnessSource>();
  const now = Date.now();
  const checkedAt = new Date(now).toISOString();
  const transitions: FreshnessEvaluation["transitions"] = [];
  const statements: ReturnType<(typeof env.DB)["prepare"]>[] = [];
  let breached = 0;
  for (const source of rows.results) {
    const state = freshnessState(source, now);
    if (state.status === "breached") breached += 1;
    if (state.status !== source.freshnessStatus) {
      transitions.push({
        sourceId: source.id,
        sourceName: source.name,
        from: source.freshnessStatus,
        to: state.status,
        lagMinutes: state.lagMinutes,
        slaMinutes: source.freshnessSlaMinutes,
      });
    }
    // The same identifier is accepted by SQLite/D1 and the production
    // PostgreSQL UUID column. The uniqueness constraint, not a synthetic ID,
    // is responsible for deduplicating the source-level alert.
    const alertId = crypto.randomUUID();
    const summary = source.lastSuccessfulObjectAt
      ? `${source.name} is ${state.lagMinutes} minutes behind its ${source.freshnessSlaMinutes}-minute freshness objective.`
      : `${source.name} has not synchronized AWS evidence within its ${source.freshnessSlaMinutes}-minute freshness objective.`;
    statements.push(
      env.DB.prepare(
        `UPDATE ingestion_sources SET freshness_status = ?, freshness_checked_at = ?,
            freshness_lag_minutes = ? WHERE id = ? AND workspace_id = 'default'`,
      ).bind(state.status, checkedAt, state.lagMinutes, source.id),
    );
    if (state.status === "breached") {
      statements.push(
        env.DB.prepare(
          `INSERT INTO ingestion_source_alerts
            (id, workspace_id, source_id, alert_type, status, severity, summary,
             first_observed_at, last_observed_at, resolved_at)
           VALUES (?, 'default', ?, 'freshness-breach', 'open', 'high', ?, ?, ?, '')
           ON CONFLICT(workspace_id, source_id, alert_type) DO UPDATE SET
             status = 'open', severity = 'high', summary = excluded.summary,
             last_observed_at = excluded.last_observed_at, resolved_at = ''`,
        ).bind(alertId, source.id, summary, checkedAt, checkedAt),
      );
    } else {
      statements.push(
        env.DB.prepare(
          `UPDATE ingestion_source_alerts SET status = 'resolved', resolved_at = ?,
              last_observed_at = ?
           WHERE workspace_id = 'default' AND source_id = ?
             AND alert_type = 'freshness-breach' AND status = 'open'`,
        ).bind(checkedAt, checkedAt, source.id),
      );
    }
  }
  // Preserve each source update + alert pair in the same bounded D1 batch while
  // avoiding one remote database round-trip per source at organization scale.
  for (let offset = 0; offset < statements.length; offset += 100) {
    await env.DB.batch(statements.slice(offset, offset + 100));
  }
  return { checked: rows.results.length, breached, transitions };
}
