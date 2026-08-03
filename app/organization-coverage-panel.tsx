"use client";

import {
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleX,
  CloudCog,
  Database,
  RefreshCw,
  Search,
  ServerCog,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import type {
  OrganizationCoverage,
  OrganizationCoverageAccount,
} from "../lib/organization-coverage";

type LegacyCoverage = {
  coveragePercent: number;
  accountCount: number;
  accountsExpected: number;
  regionCount: number;
  regionsExpected: number;
  groupCount: number;
  ruleCount: number;
  freshnessMinutes: number;
  complete: boolean;
};

type AccountFilter = "all" | "attention" | "failed";

const PAGE_SIZE = 25;

async function fetchCoverage() {
  const response = await fetch("/api/coverage", {
    headers: { accept: "application/json" },
  });
  const body = (await response.json()) as {
    coverage?: OrganizationCoverage;
    error?: string;
  };
  if (!response.ok || !body.coverage) {
    throw new Error(body.error || "Coverage is unavailable.");
  }
  return body.coverage;
}

function dateTime(value: string) {
  const date = new Date(value);
  return Number.isFinite(date.getTime())
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date)
    : "Not available";
}

function duration(start: string, end: string) {
  const milliseconds = Date.parse(end) - Date.parse(start);
  if (!Number.isFinite(milliseconds) || milliseconds < 0) return "—";
  const minutes = Math.floor(milliseconds / 60_000);
  const seconds = Math.floor((milliseconds % 60_000) / 1000);
  return minutes ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

function statusLabel(value: OrganizationCoverageAccount["status"]) {
  if (value === "succeeded") return "Collected";
  if (value === "partial") return "Partial";
  if (value === "failed") return "Failed";
  return "Incomplete";
}

export default function OrganizationCoveragePanel({
  legacy,
  refreshSignal,
}: {
  legacy: LegacyCoverage | null;
  refreshSignal: boolean;
}) {
  const [coverage, setCoverage] = useState<OrganizationCoverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<AccountFilter>("all");
  const [page, setPage] = useState(1);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setCoverage(await fetchCoverage());
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Coverage is unavailable.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (refreshSignal) return undefined;
    let cancelled = false;
    void fetchCoverage()
      .then((value) => {
        if (!cancelled) {
          setCoverage(value);
          setError("");
        }
      })
      .catch((reason) => {
        if (!cancelled) {
          setError(reason instanceof Error ? reason.message : "Coverage is unavailable.");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshSignal]);

  const filtered = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return (coverage?.accounts ?? []).filter((account) => {
      const matchesQuery = !normalizedQuery
        || account.accountId.includes(normalizedQuery)
        || account.accountName.toLowerCase().includes(normalizedQuery);
      const matchesFilter = filter === "all"
        || (filter === "attention" && account.status !== "succeeded")
        || (filter === "failed" && account.status === "failed");
      return matchesQuery && matchesFilter;
    });
  }, [coverage, filter, query]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, pageCount);
  const visibleAccounts = filtered.slice(
    (currentPage - 1) * PAGE_SIZE,
    currentPage * PAGE_SIZE,
  );
  const summary = coverage?.summary;

  return (
    <section className="organization-coverage-stack" aria-labelledby="organization-coverage-title">
      <div className="coverage-run-grid">
        <article className="panel coverage-run-card coverage-run-primary">
          <div className="coverage-run-heading">
            <span><CloudCog size={19} /></span>
            <div>
              <p>Latest organization run</p>
              <h2 id="organization-coverage-title">
                {coverage ? `${coverage.coveragePercent}% collected` : legacy ? `${legacy.coveragePercent}% snapshot coverage` : "Awaiting evidence"}
              </h2>
            </div>
            {coverage ? (
              <em className={`coverage-run-state coverage-run-${coverage.status}`}>
                {coverage.status === "succeeded" ? <CheckCircle2 size={14} /> : coverage.status === "partial" ? <AlertTriangle size={14} /> : <CircleX size={14} />}
                {coverage.status}
              </em>
            ) : null}
          </div>
          <div className="coverage-run-progress" aria-label={`${coverage?.coveragePercent ?? legacy?.coveragePercent ?? 0}% collection coverage`}>
            <span style={{ width: `${coverage?.coveragePercent ?? legacy?.coveragePercent ?? 0}%` }} />
          </div>
          <div className="coverage-run-meta">
            <span>
              <strong>{coverage ? dateTime(coverage.completedAt) : legacy ? `${legacy.freshnessMinutes} minutes ago` : "Not connected"}</strong>
              <small>Completed</small>
            </span>
            <span>
              <strong>{coverage ? duration(coverage.startedAt, coverage.completedAt) : "—"}</strong>
              <small>Run duration</small>
            </span>
            <span>
              <strong>{coverage?.runId.slice(0, 8) || "—"}</strong>
              <small>Run ID</small>
            </span>
          </div>
        </article>
        <article className="panel coverage-metric-card">
          <span className="coverage-metric-icon"><ServerCog size={18} /></span>
          <p>Accounts</p>
          <strong>{summary ? `${summary.accountsSucceeded}/${summary.accountsExpected}` : legacy ? `${legacy.accountCount}/${legacy.accountsExpected}` : "—"}</strong>
          <small>{summary ? `${summary.accountsPartial} partial · ${summary.accountsFailed} failed · ${summary.accountsIncomplete} incomplete` : "Authenticated organization accounts"}</small>
        </article>
        <article className="panel coverage-metric-card">
          <span className="coverage-metric-icon"><CloudCog size={18} /></span>
          <p>Account-Regions</p>
          <strong>{summary ? `${summary.regionsSucceeded}/${summary.regionsExpected}` : legacy ? `${legacy.regionCount}/${legacy.regionsExpected}` : "—"}</strong>
          <small>{summary ? `${summary.regionsFailed} failed · ${summary.regionsIncomplete} incomplete` : "Scanned targets"}</small>
        </article>
        <article className="panel coverage-metric-card">
          <span className="coverage-metric-icon"><Database size={18} /></span>
          <p>Inventory</p>
          <strong>{(summary?.securityGroupCount ?? legacy?.groupCount ?? 0).toLocaleString()}</strong>
          <small>{(summary?.securityGroupRuleCount ?? legacy?.ruleCount ?? 0).toLocaleString()} rules observed</small>
        </article>
      </div>

      {error && !coverage ? (
        <div className="coverage-transition-note" role="status">
          <AlertTriangle size={18} />
          <div>
            <strong>Organization manifest not connected</strong>
            <p>{error} The legacy snapshot summary remains visible while the distributed collector is deployed.</p>
          </div>
          <button className="button button-secondary" onClick={() => void load()} disabled={loading}>
            <RefreshCw size={15} className={loading ? "spin" : ""} /> Retry
          </button>
        </div>
      ) : null}

      {coverage ? (
        <section className="panel organization-account-panel">
          <div className="panel-header organization-account-header">
            <div>
              <h2>Account collection health</h2>
              <p>Every account remains visible—even when authentication or a Region scan fails.</p>
            </div>
            <button className="button button-secondary" onClick={() => void load()} disabled={loading}>
              <RefreshCw size={15} className={loading ? "spin" : ""} /> Refresh manifest
            </button>
          </div>
          <div className="coverage-account-toolbar">
            <label className="coverage-account-search">
              <Search size={15} />
              <span className="sr-only">Search accounts</span>
              <input
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setPage(1);
                }}
                placeholder="Search account name or ID"
              />
            </label>
            <div className="coverage-account-filters" aria-label="Filter account collection status">
              {([
                ["all", "All accounts"],
                ["attention", "Needs attention"],
                ["failed", "Failed"],
              ] as const).map(([value, label]) => (
                <button
                  key={value}
                  className={filter === value ? "active" : ""}
                  onClick={() => {
                    setFilter(value);
                    setPage(1);
                  }}
                  aria-pressed={filter === value}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>
          <div className="coverage-account-table-wrap">
            <table className="coverage-account-table">
              <thead>
                <tr>
                  <th>Account</th>
                  <th>Status</th>
                  <th>Regions</th>
                  <th>Failures</th>
                  <th>Completed</th>
                </tr>
              </thead>
              <tbody>
                {visibleAccounts.map((account) => (
                  <tr key={account.accountId}>
                    <td>
                      <strong>{account.accountName || account.accountId}</strong>
                      <span>{account.accountId}</span>
                    </td>
                    <td>
                      <span className={`coverage-account-status coverage-account-${account.status}`}>
                        <i /> {statusLabel(account.status)}
                      </span>
                    </td>
                    <td>
                      <strong>{account.regionsSucceeded}/{account.regionsExpected}</strong>
                      <span>account-Regions</span>
                    </td>
                    <td>
                      <strong>{account.regionsFailed}</strong>
                      <span>{account.errorCode || (account.regionsFailed ? "Inspect target evidence" : "No failures")}</span>
                    </td>
                    <td>{dateTime(account.completedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!visibleAccounts.length ? (
              <div className="coverage-account-empty">
                <Search size={20} />
                <strong>No accounts match this view</strong>
                <p>Clear the search or choose a broader status filter.</p>
              </div>
            ) : null}
          </div>
          <footer className="coverage-account-pagination">
            <span>{filtered.length.toLocaleString()} account{filtered.length === 1 ? "" : "s"}</span>
            <div>
              <button
                aria-label="Previous account page"
                disabled={currentPage === 1}
                onClick={() => setPage((value) => Math.max(1, value - 1))}
              ><ChevronLeft size={15} /></button>
              <span>Page {currentPage} of {pageCount}</span>
              <button
                aria-label="Next account page"
                disabled={currentPage === pageCount}
                onClick={() => setPage((value) => Math.min(pageCount, value + 1))}
              ><ChevronRight size={15} /></button>
            </div>
          </footer>
        </section>
      ) : null}
    </section>
  );
}
