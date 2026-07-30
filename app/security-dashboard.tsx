"use client";

import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowUpRight,
  BadgeCheck,
  Bell,
  Check,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Clock3,
  CloudCog,
  Database,
  Download,
  ExternalLink,
  FileCheck2,
  Filter,
  Gauge,
  KeyRound,
  Menu,
  Network,
  RefreshCw,
  Search,
  Settings,
  ShieldCheck,
  ShieldEllipsis,
  SlidersHorizontal,
  Sparkles,
  UserRound,
  Users,
  X,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  activity,
  securityGroups,
  type ReviewStatus,
  type SecurityGroup,
  type Severity,
  weeklyExposure,
  weeklyLabels,
} from "../lib/security-data";

type View = "overview" | "inventory" | "reviews" | "activity" | "sources";
type ReviewRecord = {
  securityGroupId: string;
  status: ReviewStatus;
  assignee: string;
  note: string;
  updatedAt?: string;
};

const statusLabels: Record<ReviewStatus, string> = {
  "needs-review": "Needs review",
  "in-review": "In review",
  approved: "Approved",
  remediate: "Remediate",
  exception: "Exception",
};

const severityLabels: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

const navItems = [
  { id: "overview" as View, label: "Overview", icon: Gauge },
  { id: "inventory" as View, label: "Security groups", icon: Network },
  { id: "reviews" as View, label: "Review queue", icon: FileCheck2, count: 5 },
  { id: "activity" as View, label: "Change activity", icon: Activity },
];

function riskTone(score: number) {
  if (score >= 85) return "critical";
  if (score >= 70) return "high";
  if (score >= 45) return "medium";
  return "low";
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`severity-badge severity-${severity}`}>
      <span aria-hidden="true" />
      {severityLabels[severity]}
    </span>
  );
}

function StatusBadge({ status }: { status: ReviewStatus }) {
  return <span className={`status-badge status-${status}`}>{statusLabels[status]}</span>;
}

function RiskScore({ score }: { score: number }) {
  return (
    <div className={`risk-score risk-${riskTone(score)}`} aria-label={`Risk score ${score} out of 100`}>
      <strong>{score}</strong>
      <span>/100</span>
    </div>
  );
}

export default function SecurityDashboard() {
  const [view, setView] = useState<View>("overview");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"all" | Severity>("all");
  const [environment, setEnvironment] = useState("all");
  const [sort, setSort] = useState("risk");
  const [selectedGroup, setSelectedGroup] = useState<SecurityGroup | null>(null);
  const [reviewTarget, setReviewTarget] = useState<SecurityGroup | null>(null);
  const [reviewStatus, setReviewStatus] = useState<ReviewStatus>("in-review");
  const [reviewAssignee, setReviewAssignee] = useState("Morgan Lee");
  const [reviewNote, setReviewNote] = useState("");
  const [reviewError, setReviewError] = useState("");
  const [reviewOverrides, setReviewOverrides] = useState<Record<string, ReviewRecord>>({});
  const [saving, setSaving] = useState(false);
  const [toast, setToast] = useState("");
  const [mobileOpen, setMobileOpen] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let active = true;
    fetch("/api/reviews")
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then((payload: { reviews?: ReviewRecord[] }) => {
        if (!active) return;
        const mapped = Object.fromEntries(
          (payload.reviews ?? []).map((review) => [review.securityGroupId, review]),
        );
        setReviewOverrides(mapped);
      })
      .catch(() => {
        // The dashboard remains useful in read-only mode while its review store recovers.
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(""), 3200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  useEffect(() => {
    function handleShortcut(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setView("inventory");
        window.setTimeout(() => searchRef.current?.focus(), 0);
      }
    }
    window.addEventListener("keydown", handleShortcut);
    return () => window.removeEventListener("keydown", handleShortcut);
  }, []);

  const statusFor = (group: SecurityGroup) =>
    reviewOverrides[group.id]?.status ?? group.defaultStatus;

  const filteredGroups = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return securityGroups
      .filter((group) => {
        const matchesQuery =
          !normalized ||
          [group.name, group.id, group.accountName, group.owner, group.region, group.service]
            .join(" ")
            .toLowerCase()
            .includes(normalized);
        const matchesSeverity = severity === "all" || group.severity === severity;
        const matchesEnvironment =
          environment === "all" || group.environment.toLowerCase() === environment;
        return matchesQuery && matchesSeverity && matchesEnvironment;
      })
      .sort((a, b) => {
        if (sort === "name") return a.name.localeCompare(b.name);
        if (sort === "changed") return a.lastChanged.localeCompare(b.lastChanged);
        return b.riskScore - a.riskScore;
      });
  }, [query, severity, environment, sort]);

  const reviewQueue = securityGroups
    .filter((group) =>
      ["needs-review", "in-review", "remediate"].includes(statusFor(group)),
    )
    .sort((a, b) => b.riskScore - a.riskScore);

  function navigate(next: View) {
    setView(next);
    setMobileOpen(false);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function openReview(group: SecurityGroup) {
    const existing = reviewOverrides[group.id];
    setReviewTarget(group);
    setReviewStatus(existing?.status ?? (group.defaultStatus === "needs-review" ? "in-review" : group.defaultStatus));
    setReviewAssignee(existing?.assignee ?? (group.owner === "Unassigned" ? "Morgan Lee" : group.owner));
    setReviewNote(existing?.note ?? "");
    setReviewError("");
  }

  async function saveReview() {
    if (!reviewTarget) return;
    if (
      ["approved", "exception", "remediate"].includes(reviewStatus) &&
      reviewNote.trim().length < 8
    ) {
      setReviewError("Add a short rationale (at least 8 characters) for this decision.");
      return;
    }

    setSaving(true);
    setReviewError("");
    try {
      const response = await fetch("/api/reviews", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          securityGroupId: reviewTarget.id,
          status: reviewStatus,
          assignee: reviewAssignee,
          note: reviewNote,
        }),
      });
      const payload = (await response.json()) as { review?: ReviewRecord; error?: string };
      if (!response.ok || !payload.review) {
        throw new Error(payload.error ?? "The review could not be saved.");
      }
      setReviewOverrides((current) => ({
        ...current,
        [reviewTarget.id]: payload.review as ReviewRecord,
      }));
      setToast(`${reviewTarget.name} is now ${statusLabels[reviewStatus].toLowerCase()}.`);
      setReviewTarget(null);
    } catch (error) {
      setReviewError(
        error instanceof Error ? error.message : "The review could not be saved.",
      );
    } finally {
      setSaving(false);
    }
  }

  function exportCsv(groups: SecurityGroup[]) {
    const headers = [
      "Security group",
      "ID",
      "Account",
      "Region",
      "Environment",
      "Owner",
      "Risk score",
      "Severity",
      "Status",
      "Public rules",
      "Findings",
    ];
    const rows = groups.map((group) => [
      group.name,
      group.id,
      group.accountName,
      group.region,
      group.environment,
      group.owner,
      String(group.riskScore),
      group.severity,
      statusFor(group),
      String(group.publicRules),
      group.findings.join("; "),
    ]);
    const csv = [headers, ...rows]
      .map((row) =>
        row.map((value) => `"${value.replaceAll('"', '""')}"`).join(","),
      )
      .join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `gatewatch-security-groups-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
    setToast(`Exported ${groups.length} security groups.`);
  }

  function syncNow() {
    setSyncing(true);
    window.setTimeout(() => {
      setSyncing(false);
      setToast("AWS Config snapshot is current across 6 accounts.");
    }, 900);
  }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileOpen ? "sidebar-open" : ""}`} aria-label="Primary navigation">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={21} strokeWidth={2.2} /></div>
          <div>
            <strong>Gatewatch</strong>
            <span>Cloud posture</span>
          </div>
        </div>

        <nav className="primary-nav">
          <p className="nav-label">Workspace</p>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                className={view === item.id ? "active" : ""}
                onClick={() => navigate(item.id)}
              >
                <Icon size={18} />
                <span>{item.label}</span>
                {item.count ? <em>{reviewQueue.length}</em> : null}
              </button>
            );
          })}
          <p className="nav-label nav-label-spaced">Manage</p>
          <button className={view === "sources" ? "active" : ""} onClick={() => navigate("sources")}>
            <CloudCog size={18} />
            <span>Data sources</span>
          </button>
        </nav>

        <div className="coverage-card">
          <div className="coverage-heading">
            <span><Database size={15} /> Data coverage</span>
            <strong>98%</strong>
          </div>
          <div className="progress-track"><span style={{ width: "98%" }} /></div>
          <p>6 accounts · 4 regions</p>
          <button onClick={() => navigate("sources")}>View source health <ChevronRight size={14} /></button>
        </div>

        <div className="sidebar-user">
          <div className="avatar">ML</div>
          <div><strong>Morgan Lee</strong><span>Security Engineering</span></div>
          <button aria-label="Account menu" disabled title="Account management is available after sign-in is configured"><ChevronDown size={16} /></button>
        </div>
      </aside>

      {mobileOpen ? <button className="sidebar-scrim" aria-label="Close menu" onClick={() => setMobileOpen(false)} /> : null}

      <main className="main-content">
        <header className="topbar">
          <button className="mobile-menu" aria-label="Open menu" onClick={() => setMobileOpen(true)}>
            <Menu size={21} />
          </button>
          <div className="global-search">
            <Search size={17} />
            <input
              ref={searchRef}
              aria-label="Search security groups"
              placeholder="Search groups, accounts, owners…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onFocus={() => {
                if (view !== "inventory") setView("inventory");
              }}
            />
            <kbd>⌘ K</kbd>
          </div>
          <div className="topbar-actions">
            <div className="sync-status">
              <span className="status-dot" />
              <div><strong>AWS Config</strong><small>Synced 4 min ago</small></div>
            </div>
            <button className="icon-button" aria-label="View notifications" onClick={() => navigate("activity")}>
              <Bell size={18} />
              <span className="notification-dot" />
            </button>
          </div>
        </header>

        <div className="page-wrap">
          {view === "overview" && (
            <OverviewView
              onNavigate={navigate}
              onSelect={setSelectedGroup}
              onReview={openReview}
              onExport={() => exportCsv(securityGroups)}
              onSync={syncNow}
              syncing={syncing}
              reviewQueue={reviewQueue}
              statusFor={statusFor}
            />
          )}
          {view === "inventory" && (
            <InventoryView
              groups={filteredGroups}
              query={query}
              setQuery={setQuery}
              severity={severity}
              setSeverity={setSeverity}
              environment={environment}
              setEnvironment={setEnvironment}
              sort={sort}
              setSort={setSort}
              onSelect={setSelectedGroup}
              onExport={() => exportCsv(filteredGroups)}
              statusFor={statusFor}
              clearFilters={() => {
                setQuery("");
                setSeverity("all");
                setEnvironment("all");
              }}
            />
          )}
          {view === "reviews" && (
            <ReviewQueueView
              groups={reviewQueue}
              statusFor={statusFor}
              onSelect={setSelectedGroup}
              onReview={openReview}
              onExport={() => exportCsv(reviewQueue)}
            />
          )}
          {view === "activity" && <ActivityView />}
          {view === "sources" && <SourcesView onSync={syncNow} syncing={syncing} />}
        </div>
      </main>

      {selectedGroup ? (
        <GroupDrawer
          group={selectedGroup}
          status={statusFor(selectedGroup)}
          review={reviewOverrides[selectedGroup.id]}
          onClose={() => setSelectedGroup(null)}
          onReview={() => {
            setSelectedGroup(null);
            openReview(selectedGroup);
          }}
        />
      ) : null}

      {reviewTarget ? (
        <ReviewModal
          group={reviewTarget}
          status={reviewStatus}
          setStatus={setReviewStatus}
          assignee={reviewAssignee}
          setAssignee={setReviewAssignee}
          note={reviewNote}
          setNote={setReviewNote}
          error={reviewError}
          saving={saving}
          onClose={() => setReviewTarget(null)}
          onSave={saveReview}
        />
      ) : null}

      {toast ? (
        <div className="toast" role="status">
          <span><Check size={15} /></span>
          {toast}
          <button aria-label="Dismiss notification" onClick={() => setToast("")}><X size={15} /></button>
        </div>
      ) : null}
    </div>
  );
}

function PageHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="page-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions ? <div className="page-actions">{actions}</div> : null}
    </div>
  );
}

function OverviewView({
  onNavigate,
  onSelect,
  onReview,
  onExport,
  onSync,
  syncing,
  reviewQueue,
  statusFor,
}: {
  onNavigate: (view: View) => void;
  onSelect: (group: SecurityGroup) => void;
  onReview: (group: SecurityGroup) => void;
  onExport: () => void;
  onSync: () => void;
  syncing: boolean;
  reviewQueue: SecurityGroup[];
  statusFor: (group: SecurityGroup) => ReviewStatus;
}) {
  const highRisk = securityGroups.filter((group) => group.riskScore >= 70).length;
  const publicRules = securityGroups.reduce((total, group) => total + group.publicRules, 0);
  return (
    <>
      <PageHeader
        eyebrow="Security group posture"
        title="Good morning, Morgan."
        description="Your highest-risk exposure is concentrated in two production accounts."
        actions={
          <>
            <button className="button button-secondary" onClick={onSync} disabled={syncing}>
              <RefreshCw size={16} className={syncing ? "spin" : ""} /> {syncing ? "Syncing…" : "Sync now"}
            </button>
            <button className="button button-primary" onClick={onExport}>
              <Download size={16} /> Export report
            </button>
          </>
        }
      />

      <section className="summary-grid" aria-label="Security posture summary">
        <MetricCard icon={<Network size={18} />} label="Security groups" value="142" helper="Across 6 AWS accounts" trend="+7 this month" tone="neutral" onClick={() => onNavigate("inventory")} />
        <MetricCard icon={<CircleAlert size={18} />} label="High risk" value={String(highRisk)} helper="Score of 70 or higher" trend="2 new findings" tone="critical" onClick={() => onNavigate("reviews")} />
        <MetricCard icon={<ArrowUpRight size={18} />} label="Public rules" value={String(publicRules)} helper="Ingress or egress to internet" trend="↓ 18% in 30 days" tone="warning" onClick={() => onNavigate("inventory")} />
        <MetricCard icon={<Clock3 size={18} />} label="Reviews due" value={String(reviewQueue.length)} helper="Within the next 14 days" trend="1 overdue" tone="attention" onClick={() => onNavigate("reviews")} />
      </section>

      <div className="overview-grid">
        <section className="panel exposure-panel">
          <div className="panel-header">
            <div><h2>Public exposure trend</h2><p>Rules with a public IPv4 or IPv6 destination</p></div>
            <span className="healthy-chip"><ArrowDownToLine size={14} /> 36% lower</span>
          </div>
          <div className="chart-legend"><span><i className="legend-public" /> Public rules</span><strong>14 current</strong></div>
          <div className="bar-chart" aria-label="Public exposure decreased from 22 to 14 rules over eight weeks">
            {weeklyExposure.map((value, index) => (
              <div className="bar-column" key={weeklyLabels[index]}>
                <div className="bar-value">{value}</div>
                <div className="bar-track"><span style={{ height: `${(value / 26) * 100}%` }} /></div>
                <small>{weeklyLabels[index]}</small>
              </div>
            ))}
          </div>
        </section>

        <section className="panel posture-panel">
          <div className="panel-header">
            <div><h2>Risk distribution</h2><p>142 groups by current score</p></div>
            <button className="text-button" onClick={() => onNavigate("inventory")}>View all <ChevronRight size={14} /></button>
          </div>
          <div className="donut-wrap">
            <div className="donut" aria-label="82 percent of security groups are low or medium risk">
              <div><strong>82%</strong><span>low–medium</span></div>
            </div>
            <div className="risk-legend">
              <div><span className="dot-critical" /><p>Critical</p><strong>2</strong></div>
              <div><span className="dot-high" /><p>High</p><strong>9</strong></div>
              <div><span className="dot-medium" /><p>Medium</p><strong>38</strong></div>
              <div><span className="dot-low" /><p>Low</p><strong>93</strong></div>
            </div>
          </div>
        </section>
      </div>

      <section className="panel review-panel">
        <div className="panel-header">
          <div><h2>Priority review queue</h2><p>Ordered by exposure, asset sensitivity, and review age</p></div>
          <button className="text-button" onClick={() => onNavigate("reviews")}>Open queue <ChevronRight size={14} /></button>
        </div>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Security group</th><th>Account / region</th><th>Primary concern</th><th>Risk</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>
              {reviewQueue.slice(0, 4).map((group) => (
                <tr key={group.id}>
                  <td>
                    <button className="group-link" onClick={() => onSelect(group)}>
                      <span className={`resource-icon icon-${group.severity}`}><Network size={17} /></span>
                      <span><strong>{group.name}</strong><small>{group.id}</small></span>
                    </button>
                  </td>
                  <td><strong className="cell-primary">{group.accountName}</strong><small>{group.region} · {group.environment}</small></td>
                  <td><span className="finding-cell"><AlertTriangle size={15} /> {group.findings[0]}</span></td>
                  <td><RiskScore score={group.riskScore} /></td>
                  <td><StatusBadge status={statusFor(group)} /></td>
                  <td><button className="button button-small" onClick={() => onReview(group)}>Review</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="insight-banner">
        <div className="insight-icon"><Sparkles size={20} /></div>
        <div><strong>Suggested focus</strong><p>3 groups combine public administrative ports with production workloads. Reviewing those first would remove 71% of your critical-risk exposure.</p></div>
        <button className="button button-dark" onClick={() => onNavigate("reviews")}>Review critical groups <ArrowUpRight size={15} /></button>
      </section>
    </>
  );
}

function MetricCard({
  icon, label, value, helper, trend, tone, onClick,
}: {
  icon: React.ReactNode; label: string; value: string; helper: string; trend: string;
  tone: string; onClick: () => void;
}) {
  return (
    <button className="metric-card" onClick={onClick}>
      <div className={`metric-icon metric-${tone}`}>{icon}</div>
      <div className="metric-top"><span>{label}</span><ChevronRight size={15} /></div>
      <strong>{value}</strong>
      <div className="metric-bottom"><span>{helper}</span><em className={`trend-${tone}`}>{trend}</em></div>
    </button>
  );
}

function InventoryView({
  groups, query, setQuery, severity, setSeverity, environment, setEnvironment,
  sort, setSort, onSelect, onExport, statusFor, clearFilters,
}: {
  groups: SecurityGroup[]; query: string; setQuery: (value: string) => void;
  severity: "all" | Severity; setSeverity: (value: "all" | Severity) => void;
  environment: string; setEnvironment: (value: string) => void;
  sort: string; setSort: (value: string) => void; onSelect: (group: SecurityGroup) => void;
  onExport: () => void; statusFor: (group: SecurityGroup) => ReviewStatus; clearFilters: () => void;
}) {
  return (
    <>
      <PageHeader
        eyebrow="Inventory"
        title="Security groups"
        description="Search and assess rules across every connected account and region."
        actions={<button className="button button-primary" onClick={onExport}><Download size={16} /> Export {groups.length} rows</button>}
      />
      <section className="panel inventory-panel">
        <div className="filter-bar">
          <label className="table-search"><Search size={16} /><input aria-label="Filter inventory" placeholder="Search by name, ID, owner…" value={query} onChange={(event) => setQuery(event.target.value)} /></label>
          <div className="filter-select"><SlidersHorizontal size={15} /><select aria-label="Filter by severity" value={severity} onChange={(event) => setSeverity(event.target.value as "all" | Severity)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
          <div className="filter-select"><Filter size={15} /><select aria-label="Filter by environment" value={environment} onChange={(event) => setEnvironment(event.target.value)}><option value="all">All environments</option><option value="production">Production</option><option value="staging">Staging</option><option value="development">Development</option><option value="shared">Shared</option></select></div>
          <div className="filter-select sort-select"><select aria-label="Sort security groups" value={sort} onChange={(event) => setSort(event.target.value)}><option value="risk">Risk: high to low</option><option value="name">Name: A–Z</option><option value="changed">Recently changed</option></select></div>
        </div>
        <div className="result-summary"><span><strong>{groups.length}</strong> of {securityGroups.length} groups</span><span>Last evaluated 4 minutes ago</span></div>
        {groups.length ? (
          <div className="table-wrap inventory-table">
            <table>
              <thead><tr><th>Security group</th><th>Environment</th><th>Rules</th><th>Exposure</th><th>Owner</th><th>Risk</th><th>Status</th><th><span className="sr-only">Open</span></th></tr></thead>
              <tbody>
                {groups.map((group) => (
                  <tr key={group.id} onClick={() => onSelect(group)} className="clickable-row">
                    <td><div className="group-cell"><span className={`resource-icon icon-${group.severity}`}><Network size={17} /></span><span><strong>{group.name}</strong><small>{group.id} · {group.accountName}</small></span></div></td>
                    <td><span className={`environment-tag env-${group.environment.toLowerCase()}`}>{group.environment}</span><small>{group.region}</small></td>
                    <td><strong className="cell-primary">{group.inboundCount} in · {group.outboundCount} out</strong><small>{group.vpc}</small></td>
                    <td>{group.publicRules ? <span className="public-count"><ExternalLink size={13} /> {group.publicRules} public</span> : <span className="private-count"><ShieldCheck size={13} /> Private only</span>}</td>
                    <td><strong className="cell-primary">{group.owner}</strong><small>{group.service}</small></td>
                    <td><RiskScore score={group.riskScore} /></td>
                    <td><StatusBadge status={statusFor(group)} /></td>
                    <td><button className="row-open" aria-label={`Open ${group.name}`} onClick={(event) => { event.stopPropagation(); onSelect(group); }}><ChevronRight size={17} /></button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state"><div><Search size={24} /></div><h3>No security groups match</h3><p>Try a broader search or clear the selected filters.</p><button className="button button-secondary" onClick={clearFilters}>Clear filters</button></div>
        )}
      </section>
    </>
  );
}

function ReviewQueueView({
  groups, statusFor, onSelect, onReview, onExport,
}: {
  groups: SecurityGroup[]; statusFor: (group: SecurityGroup) => ReviewStatus;
  onSelect: (group: SecurityGroup) => void; onReview: (group: SecurityGroup) => void; onExport: () => void;
}) {
  return (
    <>
      <PageHeader eyebrow="Governance" title="Review queue" description="Resolve risky access with clear ownership, evidence, and decision history." actions={<button className="button button-secondary" onClick={onExport}><Download size={16} /> Export queue</button>} />
      <div className="queue-stats">
        <div><span className="queue-icon queue-critical"><AlertTriangle size={17} /></span><p><strong>{groups.filter((group) => group.severity === "critical").length}</strong><span>Critical priority</span></p></div>
        <div><span className="queue-icon queue-progress"><Clock3 size={17} /></span><p><strong>{groups.filter((group) => statusFor(group) === "in-review").length}</strong><span>In progress</span></p></div>
        <div><span className="queue-icon queue-remediate"><RefreshCw size={17} /></span><p><strong>{groups.filter((group) => statusFor(group) === "remediate").length}</strong><span>Awaiting remediation</span></p></div>
      </div>
      <section className="queue-list">
        {groups.map((group, index) => (
          <article className="review-card" key={group.id}>
            <div className="review-rank">{String(index + 1).padStart(2, "0")}</div>
            <div className="review-main">
              <div className="review-title-row">
                <div><div className="title-badges"><SeverityBadge severity={group.severity} /><StatusBadge status={statusFor(group)} /></div><button onClick={() => onSelect(group)}>{group.name}</button><p>{group.id} · {group.accountName} · {group.region}</p></div>
                <RiskScore score={group.riskScore} />
              </div>
              <div className="review-detail-grid">
                <div><span>Primary concern</span><strong><AlertTriangle size={15} /> {group.findings[0]}</strong></div>
                <div><span>Business owner</span><strong><Users size={15} /> {group.owner}</strong></div>
                <div><span>Last review</span><strong><Clock3 size={15} /> {group.lastReviewed}</strong></div>
              </div>
            </div>
            <div className="review-actions"><button className="button button-secondary" onClick={() => onSelect(group)}>View evidence</button><button className="button button-primary" onClick={() => onReview(group)}>Start review <ChevronRight size={15} /></button></div>
          </article>
        ))}
        {!groups.length ? <div className="empty-state panel"><div><BadgeCheck size={24} /></div><h3>Queue cleared</h3><p>All identified security groups have a recorded decision.</p></div> : null}
      </section>
    </>
  );
}

function ActivityView() {
  const [range, setRange] = useState("30");
  const visibleActivity = range === "7" ? activity.slice(0, 3) : activity;

  return (
    <>
      <PageHeader
        eyebrow="CloudTrail evidence"
        title="Change activity"
        description="Track rule changes and review decisions across connected AWS accounts."
        actions={
          <label className="filter-select activity-range">
            <Filter size={15} />
            <select
              aria-label="Activity date range"
              value={range}
              onChange={(event) => setRange(event.target.value)}
            >
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
              <option value="90">Last 90 days</option>
            </select>
          </label>
        }
      />
      <div className="activity-layout">
        <section className="panel activity-panel">
          <div className="panel-header"><div><h2>Recent events</h2><p>CloudTrail management events and Gatewatch decisions</p></div><span className="live-chip"><span /> Live</span></div>
          <div className="timeline">
            {visibleActivity.map((item) => (
              <div className="timeline-item" key={`${item.group}-${item.time}`}>
                <span className={`timeline-icon timeline-${item.tone}`}>{item.tone === "positive" ? <Check size={16} /> : <Activity size={16} />}</span>
                <div><strong>{item.action}</strong><p><button>{item.group}</button> · by {item.actor}</p></div><time>{item.time}</time>
              </div>
            ))}
          </div>
        </section>
        <aside className="activity-side">
          <section className="panel event-summary"><h2>Event summary</h2><div><span>Ingress authorized</span><strong>18</strong></div><div><span>Ingress revoked</span><strong>26</strong></div><div><span>Egress changed</span><strong>11</strong></div><div><span>Review decisions</span><strong>9</strong></div></section>
          <section className="panel source-note"><KeyRound size={20} /><h3>Evidence integrity</h3><p>Events are linked to the originating CloudTrail event ID and retained for 365 days.</p><button disabled title="Policy editing requires an authenticated administrator">Review retention policy <ChevronRight size={14} /></button></section>
        </aside>
      </div>
    </>
  );
}

function SourcesView({ onSync, syncing }: { onSync: () => void; syncing: boolean }) {
  const sources = [
    { name: "AWS Config aggregator", detail: "Organization-wide · 6 accounts", status: "Healthy", time: "4 min ago", icon: Database },
    { name: "CloudTrail Lake", detail: "Management events · 4 regions", status: "Healthy", time: "2 min ago", icon: Activity },
    { name: "AWS Organizations", detail: "Account and OU inventory", status: "Healthy", time: "18 min ago", icon: Network },
  ];
  return (
    <>
      <PageHeader eyebrow="Integrations" title="Data sources" description="Monitor the evidence feeding security-group analysis and reporting." actions={<button className="button button-primary" onClick={onSync} disabled={syncing}><RefreshCw size={16} className={syncing ? "spin" : ""} /> {syncing ? "Syncing…" : "Sync all sources"}</button>} />
      <section className="source-health-banner"><span><CircleCheck size={21} /></span><div><strong>All data sources are healthy</strong><p>142 security groups were evaluated against 18 policy checks four minutes ago.</p></div><em>98% coverage</em></section>
      <section className="panel sources-panel">
        <div className="panel-header"><div><h2>Connected sources</h2><p>Read-only roles and organization aggregators</p></div><button className="button button-secondary" disabled title="Connection editing requires AWS administrator credentials"><Settings size={15} /> Connection settings</button></div>
        <div className="source-list">
          {sources.map((source) => {
            const Icon = source.icon;
            return <div className="source-row" key={source.name}><span className="source-icon"><Icon size={19} /></span><div><strong>{source.name}</strong><p>{source.detail}</p></div><span className="source-status"><i /> {source.status}</span><time>Synced {source.time}</time><button aria-label={`Open ${source.name}`} disabled title="Source configuration is read-only in this version"><ChevronRight size={17} /></button></div>;
          })}
        </div>
      </section>
      <section className="panel collection-panel"><div><span className="collection-icon"><CloudCog size={20} /></span><h2>Collection scope</h2></div><div className="scope-grid"><div><span>AWS accounts</span><strong>6 connected</strong><small>All organization accounts</small></div><div><span>Regions</span><strong>4 enabled</strong><small>us-east-1, us-east-2, us-west-2, eu-west-1</small></div><div><span>Evaluation interval</span><strong>Every 15 minutes</strong><small>Event-driven refresh enabled</small></div></div></section>
    </>
  );
}

function GroupDrawer({
  group, status, review, onClose, onReview,
}: {
  group: SecurityGroup; status: ReviewStatus; review?: ReviewRecord; onClose: () => void; onReview: () => void;
}) {
  return (
    <div className="drawer-layer" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
      <button className="drawer-scrim" aria-label="Close details" onClick={onClose} />
      <aside className="group-drawer">
        <div className="drawer-header">
          <div><p>Security group</p><h2 id="drawer-title">{group.name}</h2><span>{group.id}</span></div>
          <button className="icon-button" aria-label="Close details" onClick={onClose}><X size={18} /></button>
        </div>
        <div className="drawer-risk">
          <div className={`score-ring score-${group.severity}`}><strong>{group.riskScore}</strong><span>risk</span></div>
          <div><div className="title-badges"><SeverityBadge severity={group.severity} /><StatusBadge status={status} /></div><p>{group.findings.length ? `${group.findings.length} findings require attention` : "No active findings"}</p></div>
          <button className="button button-primary" onClick={onReview}>Record review</button>
        </div>
        <div className="drawer-tabs" role="tablist"><button className="active" role="tab" aria-selected="true">Rules</button><button role="tab" aria-selected="false" disabled title="Available after live AWS connection">Change history</button><button role="tab" aria-selected="false" disabled title="Available after live AWS connection">Relationships</button></div>
        <div className="drawer-body">
          <section className="detail-grid">
            <div><span>Account</span><strong>{group.accountName}</strong><small>{group.accountId}</small></div>
            <div><span>Region / VPC</span><strong>{group.region}</strong><small>{group.vpc}</small></div>
            <div><span>Owner</span><strong>{group.owner}</strong><small>{group.service}</small></div>
            <div><span>Last changed</span><strong>{group.lastChanged}</strong><small>{group.changedBy}</small></div>
          </section>
          {group.findings.length ? <section className="findings-box"><div className="findings-title"><AlertTriangle size={17} /><strong>Why this needs attention</strong></div>{group.findings.map((finding) => <div className="finding-row" key={finding}><span /><p>{finding}</p></div>)}</section> : null}
          <section className="rules-section">
            <div className="section-heading"><div><h3>Effective rules</h3><p>{group.inboundCount} ingress · {group.outboundCount} egress in AWS Config</p></div><button className="text-button" disabled title="A live AWS console link requires account federation">Open in AWS <ExternalLink size={13} /></button></div>
            <div className="rule-list">
              {group.rules.map((rule) => (
                <div className="rule-row" key={rule.id}>
                  <span className={`direction-icon direction-${rule.direction.toLowerCase()}`}>{rule.direction === "Ingress" ? <ArrowDownToLine size={15} /> : <ArrowUpRight size={15} />}</span>
                  <div className="rule-main"><div><strong>{rule.direction}</strong><span>{rule.protocol} · {rule.ports}</span></div><p>{rule.sourceLabel}<code>{rule.source}</code></p>{rule.finding ? <em><AlertTriangle size={12} /> {rule.finding}</em> : null}</div>
                  <span className={`exposure exposure-${rule.exposure.toLowerCase()}`}>{rule.exposure}</span>
                </div>
              ))}
            </div>
          </section>
          {review?.note ? <section className="review-note"><span><FileCheck2 size={17} /></span><div><strong>Latest review note</strong><p>{review.note}</p><small>{review.assignee} · {review.updatedAt ?? "Recently"}</small></div></section> : null}
        </div>
      </aside>
    </div>
  );
}

function ReviewModal({
  group, status, setStatus, assignee, setAssignee, note, setNote, error, saving, onClose, onSave,
}: {
  group: SecurityGroup; status: ReviewStatus; setStatus: (value: ReviewStatus) => void;
  assignee: string; setAssignee: (value: string) => void; note: string; setNote: (value: string) => void;
  error: string; saving: boolean; onClose: () => void; onSave: () => void;
}) {
  return (
    <div className="modal-layer" role="dialog" aria-modal="true" aria-labelledby="review-title">
      <button className="modal-scrim" aria-label="Close review" onClick={onClose} />
      <div className="review-modal">
        <div className="modal-header"><div><p>Security review</p><h2 id="review-title">{group.name}</h2><span>{group.id} · Risk score {group.riskScore}</span></div><button className="icon-button" aria-label="Close review" onClick={onClose}><X size={18} /></button></div>
        <div className="modal-body">
          <div className="review-warning"><AlertTriangle size={17} /><p><strong>{group.findings[0]}</strong><span>{group.publicRules} public rule{group.publicRules === 1 ? "" : "s"} · Last reviewed {group.lastReviewed.toLowerCase()}</span></p></div>
          <fieldset className="decision-fieldset"><legend>Decision</legend><div className="decision-grid">
            {([
              ["in-review", "Continue review", Clock3],
              ["approved", "Approve access", BadgeCheck],
              ["remediate", "Request fix", RefreshCw],
              ["exception", "Accept exception", ShieldEllipsis],
            ] as const).map(([value, label, Icon]) => (
              <label className={status === value ? "selected" : ""} key={value}><input type="radio" name="decision" value={value} checked={status === value} onChange={() => setStatus(value)} /><Icon size={17} /><span>{label}</span><Check size={15} className="decision-check" /></label>
            ))}
          </div></fieldset>
          <label className="form-field"><span>Assignee</span><div className="input-with-icon"><UserRound size={16} /><select value={assignee} onChange={(event) => setAssignee(event.target.value)}><option>Morgan Lee</option><option>Payments Platform</option><option>Cloud Operations</option><option>Data Reliability</option><option>Analytics Engineering</option><option>Commerce Runtime</option></select></div></label>
          <label className="form-field"><span>Review rationale {status === "in-review" ? <em>Optional</em> : <em>Required</em>}</span><textarea value={note} onChange={(event) => setNote(event.target.value)} maxLength={1200} placeholder="Document the business justification, compensating controls, or required remediation…" /><small>{note.length}/1200</small></label>
          {error ? <div className="form-error" role="alert"><CircleAlert size={15} /> {error}</div> : null}
        </div>
        <div className="modal-footer"><button className="button button-secondary" onClick={onClose}>Cancel</button><button className="button button-primary" onClick={onSave} disabled={saving}>{saving ? <><RefreshCw size={15} className="spin" /> Saving…</> : <>Save decision <ChevronRight size={15} /></>}</button></div>
      </div>
    </div>
  );
}
