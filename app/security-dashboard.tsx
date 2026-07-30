"use client";

import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  BadgeCheck,
  Bell,
  Box,
  Braces,
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
  Eye,
  FileCheck2,
  Filter,
  Gauge,
  GitPullRequest,
  KeyRound,
  Menu,
  Network,
  Radio,
  RefreshCw,
  Route,
  Search,
  Settings,
  ShieldAlert,
  ShieldCheck,
  ShieldEllipsis,
  SlidersHorizontal,
  Sparkles,
  UserRound,
  Users,
  Workflow,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  activity,
  policyChecks,
  securityGroups,
  type ReviewStatus,
  type SecurityGroup,
  type Severity,
  weeklyExposure,
  weeklyLabels,
} from "../lib/security-data";

type View =
  | "overview"
  | "inventory"
  | "connectivity"
  | "reviews"
  | "activity"
  | "sources";

type DrawerTab = "evidence" | "connectivity" | "change" | "risk";

type ReviewRecord = {
  securityGroupId: string;
  status: ReviewStatus;
  assignee: string;
  reviewer?: string;
  note: string;
  ticketRef?: string;
  expiresAt?: string;
  evidenceSnapshot?: string;
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
  return (
    <span className={`status-badge status-${status}`}>
      {statusLabels[status]}
    </span>
  );
}

function RiskScore({
  score,
  projected,
}: {
  score: number;
  projected?: number;
}) {
  return (
    <div
      className={`risk-score risk-${riskTone(score)}`}
      aria-label={`Risk score ${score} out of 100`}
    >
      <strong>{score}</strong>
      <span>/100</span>
      {projected !== undefined ? (
        <em>
          <ArrowRight size={11} /> {projected}
        </em>
      ) : null}
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
  const [reviewStatus, setReviewStatus] =
    useState<ReviewStatus>("in-review");
  const [reviewAssignee, setReviewAssignee] = useState("Morgan Lee");
  const [reviewNote, setReviewNote] = useState("");
  const [reviewTicket, setReviewTicket] = useState("");
  const [reviewExpiry, setReviewExpiry] = useState("");
  const [reviewError, setReviewError] = useState("");
  const [reviewOverrides, setReviewOverrides] = useState<
    Record<string, ReviewRecord>
  >({});
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
        setReviewOverrides(
          Object.fromEntries(
            (payload.reviews ?? []).map((review) => [
              review.securityGroupId,
              review,
            ]),
          ),
        );
      })
      .catch(() => {
        // Evidence views remain available if the durable review store is recovering.
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
      if (event.key === "Escape") {
        setSelectedGroup(null);
        setReviewTarget(null);
        setMobileOpen(false);
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
        const searchText = [
          group.name,
          group.id,
          group.accountName,
          group.owner,
          group.region,
          group.service,
          group.findings.join(" "),
          group.intent.application,
        ]
          .join(" ")
          .toLowerCase();
        return (
          (!normalized || searchText.includes(normalized)) &&
          (severity === "all" || group.severity === severity) &&
          (environment === "all" ||
            group.environment.toLowerCase() === environment)
        );
      })
      .sort((a, b) => {
        if (sort === "name") return a.name.localeCompare(b.name);
        if (sort === "traffic")
          return b.traffic.accepted30d - a.traffic.accepted30d;
        if (sort === "changed")
          return a.lastChanged.localeCompare(b.lastChanged);
        return b.riskScore - a.riskScore;
      });
  }, [environment, query, severity, sort]);

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
    setReviewStatus(
      existing?.status ??
        (group.defaultStatus === "needs-review"
          ? "in-review"
          : group.defaultStatus),
    );
    setReviewAssignee(
      existing?.assignee ??
        (group.owner === "Unassigned" ? "Morgan Lee" : group.owner),
    );
    setReviewNote(existing?.note ?? "");
    setReviewTicket(existing?.ticketRef ?? group.intent.ticket);
    setReviewExpiry(existing?.expiresAt ?? group.intent.expiresAt ?? "");
    setReviewError("");
  }

  async function saveReview() {
    if (!reviewTarget) return;
    if (
      ["approved", "exception", "remediate"].includes(reviewStatus) &&
      reviewNote.trim().length < 12
    ) {
      setReviewError(
        "Document the decision rationale using at least 12 characters.",
      );
      return;
    }
    if (reviewStatus === "exception" && !reviewExpiry) {
      setReviewError("Every accepted exception needs an expiration date.");
      return;
    }
    if (
      ["approved", "exception", "remediate"].includes(reviewStatus) &&
      !reviewTicket.trim()
    ) {
      setReviewError("Link this decision to a ticket or pull request.");
      return;
    }

    setSaving(true);
    setReviewError("");
    try {
      const evidenceSnapshot = [
        `risk:${reviewTarget.riskScore}`,
        `paths:${reviewTarget.paths.filter((path) => path.status === "reachable").length}`,
        `flows30d:${reviewTarget.traffic.accepted30d}`,
        `intent:${reviewTarget.intent.status}`,
        `event:${reviewTarget.change.eventId}`,
      ].join("|");
      const response = await fetch("/api/reviews", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          securityGroupId: reviewTarget.id,
          status: reviewStatus,
          assignee: reviewAssignee,
          note: reviewNote,
          ticketRef: reviewTicket,
          expiresAt: reviewStatus === "exception" ? reviewExpiry : "",
          evidenceSnapshot,
        }),
      });
      const payload = (await response.json()) as {
        review?: ReviewRecord;
        error?: string;
      };
      if (!response.ok || !payload.review) {
        throw new Error(payload.error ?? "The review could not be saved.");
      }
      setReviewOverrides((current) => ({
        ...current,
        [reviewTarget.id]: payload.review as ReviewRecord,
      }));
      setToast(
        `${reviewTarget.name} is now ${statusLabels[
          reviewStatus
        ].toLowerCase()}. Evidence was snapshotted.`,
      );
      setReviewTarget(null);
    } catch (error) {
      setReviewError(
        error instanceof Error
          ? error.message
          : "The review could not be saved.",
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
      "Application",
      "Risk score",
      "Projected risk",
      "Severity",
      "Status",
      "Confirmed paths",
      "Flow coverage",
      "Intent status",
      "Change channel",
      "Findings",
    ];
    const rows = groups.map((group) => [
      group.name,
      group.id,
      group.accountName,
      group.region,
      group.environment,
      group.owner,
      group.intent.application,
      String(group.riskScore),
      String(group.projectedRisk),
      group.severity,
      statusFor(group),
      String(group.paths.filter((path) => path.status === "reachable").length),
      `${group.traffic.coverage}%`,
      group.intent.status,
      group.change.channel,
      group.findings.join("; "),
    ]);
    const csv = [headers, ...rows]
      .map((row) =>
        row.map((value) => `"${value.replaceAll('"', '""')}"`).join(","),
      )
      .join("\n");
    const url = URL.createObjectURL(
      new Blob([csv], { type: "text/csv;charset=utf-8" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `gatewatch-evidence-report-${new Date()
      .toISOString()
      .slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
    setToast(`Exported ${groups.length} evidence-backed records.`);
  }

  function syncNow() {
    setSyncing(true);
    window.setTimeout(() => {
      setSyncing(false);
      setToast(
        "Config, CloudTrail, Flow Logs, and Inspector evidence are current.",
      );
    }, 900);
  }

  const navItems = [
    { id: "overview" as View, label: "Posture", icon: Gauge },
    { id: "inventory" as View, label: "Findings", icon: ShieldAlert },
    { id: "connectivity" as View, label: "Connectivity", icon: Route },
    {
      id: "reviews" as View,
      label: "Review queue",
      icon: FileCheck2,
      count: reviewQueue.length,
    },
    { id: "activity" as View, label: "Change evidence", icon: Activity },
  ];

  return (
    <div className="app-shell">
      <aside
        className={`sidebar ${mobileOpen ? "sidebar-open" : ""}`}
        aria-label="Primary navigation"
      >
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={21} strokeWidth={2.2} />
          </div>
          <div>
            <strong>Gatewatch</strong>
            <span>Cloud posture</span>
          </div>
        </div>

        <nav className="primary-nav">
          <p className="nav-label">Investigate</p>
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
                {item.count ? <em>{item.count}</em> : null}
              </button>
            );
          })}
          <p className="nav-label nav-label-spaced">Manage</p>
          <button
            className={view === "sources" ? "active" : ""}
            onClick={() => navigate("sources")}
          >
            <CloudCog size={18} />
            <span>Data sources</span>
          </button>
        </nav>

        <div className="coverage-card">
          <div className="coverage-heading">
            <span>
              <Radio size={15} /> Evidence coverage
            </span>
            <strong>96%</strong>
          </div>
          <div className="progress-track">
            <span style={{ width: "96%" }} />
          </div>
          <p>6 accounts · 4 regions · 5 sources</p>
          <button onClick={() => navigate("sources")}>
            Inspect coverage <ChevronRight size={14} />
          </button>
        </div>

        <div className="sidebar-user">
          <div className="avatar">ML</div>
          <div>
            <strong>Morgan Lee</strong>
            <span>Security Engineering</span>
          </div>
          <button
            aria-label="Account menu"
            disabled
            title="Account management is available after sign-in is configured"
          >
            <ChevronDown size={16} />
          </button>
        </div>
      </aside>

      {mobileOpen ? (
        <button
          className="sidebar-scrim"
          aria-label="Close menu"
          onClick={() => setMobileOpen(false)}
        />
      ) : null}

      <main className="main-content">
        <header className="topbar">
          <button
            className="mobile-menu"
            aria-label="Open menu"
            onClick={() => setMobileOpen(true)}
          >
            <Menu size={21} />
          </button>
          <div className="global-search">
            <Search size={17} />
            <input
              ref={searchRef}
              aria-label="Search findings and security groups"
              placeholder="Search groups, findings, owners…"
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
              <div>
                <strong>Evidence current</strong>
                <small>Evaluated 4 min ago</small>
              </div>
            </div>
            <button
              className="icon-button"
              aria-label="View change evidence"
              onClick={() => navigate("activity")}
            >
              <Bell size={18} />
              <span className="notification-dot" />
            </button>
          </div>
        </header>

        <div className="page-wrap">
          {view === "overview" ? (
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
          ) : null}
          {view === "inventory" ? (
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
          ) : null}
          {view === "connectivity" ? (
            <ConnectivityView
              onSelect={setSelectedGroup}
              onReview={openReview}
            />
          ) : null}
          {view === "reviews" ? (
            <ReviewQueueView
              groups={reviewQueue}
              statusFor={statusFor}
              onSelect={setSelectedGroup}
              onReview={openReview}
              onExport={() => exportCsv(reviewQueue)}
            />
          ) : null}
          {view === "activity" ? (
            <ActivityView onSelect={setSelectedGroup} />
          ) : null}
          {view === "sources" ? (
            <SourcesView onSync={syncNow} syncing={syncing} />
          ) : null}
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
          ticket={reviewTicket}
          setTicket={setReviewTicket}
          expiry={reviewExpiry}
          setExpiry={setReviewExpiry}
          error={reviewError}
          saving={saving}
          onClose={() => setReviewTarget(null)}
          onSave={saveReview}
        />
      ) : null}

      {toast ? (
        <div className="toast" role="status">
          <span>
            <Check size={15} />
          </span>
          {toast}
          <button
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={15} />
          </button>
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

function MetricCard({
  icon,
  label,
  value,
  helper,
  trend,
  tone,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  helper: string;
  trend: string;
  tone: string;
  onClick: () => void;
}) {
  return (
    <button className="metric-card" onClick={onClick}>
      <div className={`metric-icon metric-${tone}`}>{icon}</div>
      <div className="metric-top">
        <span>{label}</span>
        <ChevronRight size={15} />
      </div>
      <strong>{value}</strong>
      <div className="metric-bottom">
        <span>{helper}</span>
        <em className={`trend-${tone}`}>{trend}</em>
      </div>
    </button>
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
  const reachableAssets = new Set(
    securityGroups
      .filter((group) =>
        group.paths.some(
          (path) =>
            path.status === "reachable" && path.source === "Internet",
        ),
      )
      .flatMap((group) => group.attachments.map((attachment) => attachment.id)),
  ).size;
  const drifted = securityGroups.filter(
    (group) => group.intent.status !== "matched",
  ).length;
  const outOfWorkflow = securityGroups.filter(
    (group) => !group.change.approved,
  ).length;
  return (
    <>
      <PageHeader
        eyebrow="Evidence-backed posture"
        title="Focus on reachable risk."
        description="Priorities now combine deployed access, network paths, observed traffic, asset criticality, vulnerabilities, and policy intent."
        actions={
          <>
            <button
              className="button button-secondary"
              onClick={onSync}
              disabled={syncing}
            >
              <RefreshCw size={16} className={syncing ? "spin" : ""} />
              {syncing ? "Evaluating…" : "Refresh evidence"}
            </button>
            <button className="button button-primary" onClick={onExport}>
              <Download size={16} /> Export evidence
            </button>
          </>
        }
      />

      <section className="summary-grid" aria-label="Security posture summary">
        <MetricCard
          icon={<Route size={18} />}
          label="Internet-reachable assets"
          value={String(reachableAssets)}
          helper="Confirmed paths, not rule-only"
          trend="3 critical"
          tone="critical"
          onClick={() => onNavigate("connectivity")}
        />
        <MetricCard
          icon={<Workflow size={18} />}
          label="Intent drift"
          value={String(drifted)}
          helper="Actual access exceeds policy"
          trend="2 undocumented"
          tone="warning"
          onClick={() => onNavigate("inventory")}
        />
        <MetricCard
          icon={<GitPullRequest size={18} />}
          label="Out-of-workflow"
          value={String(outOfWorkflow)}
          helper="Console or unapproved changes"
          trend="2 need review"
          tone="attention"
          onClick={() => onNavigate("activity")}
        />
        <MetricCard
          icon={<Clock3 size={18} />}
          label="Reviews due"
          value={String(reviewQueue.length)}
          helper="Evidence ready for decision"
          trend="1 overdue"
          tone="neutral"
          onClick={() => onNavigate("reviews")}
        />
      </section>

      <section className="evidence-callout" aria-label="Evidence coverage">
        <div className="evidence-callout-icon">
          <Eye size={20} />
        </div>
        <div>
          <strong>96% of findings have complete evidence</strong>
          <p>
            Config state, CloudTrail provenance, Flow Log usage, and Inspector
            context were correlated in the latest evaluation.
          </p>
        </div>
        <div className="evidence-pills">
          <span>
            <CircleCheck size={13} /> Config
          </span>
          <span>
            <CircleCheck size={13} /> CloudTrail
          </span>
          <span>
            <CircleCheck size={13} /> Flow Logs
          </span>
          <span>
            <CircleCheck size={13} /> Inspector
          </span>
        </div>
      </section>

      <div className="overview-grid">
        <section className="panel exposure-panel">
          <div className="panel-header">
            <div>
              <h2>Confirmed exposure trend</h2>
              <p>Public rules with an effective network path</p>
            </div>
            <span className="healthy-chip">
              <ArrowDownToLine size={14} /> 36% lower
            </span>
          </div>
          <div className="chart-legend">
            <span>
              <i className="legend-public" /> Reachable rules
            </span>
            <strong>14 current</strong>
          </div>
          <div
            className="bar-chart"
            aria-label="Confirmed exposure decreased from 22 to 14 rules over eight weeks"
          >
            {weeklyExposure.map((value, index) => (
              <div className="bar-column" key={weeklyLabels[index]}>
                <div className="bar-value">{value}</div>
                <div className="bar-track">
                  <span style={{ height: `${(value / 26) * 100}%` }} />
                </div>
                <small>{weeklyLabels[index]}</small>
              </div>
            ))}
          </div>
        </section>

        <section className="panel signal-panel">
          <div className="panel-header">
            <div>
              <h2>Signal quality</h2>
              <p>Why today’s ranking is trustworthy</p>
            </div>
          </div>
          <div className="signal-list">
            <div>
              <span className="signal-icon signal-red">
                <Route size={17} />
              </span>
              <p>
                <strong>5 effective paths</strong>
                <span>Confirmed with route and attachment context</span>
              </p>
            </div>
            <div>
              <span className="signal-icon signal-violet">
                <Zap size={17} />
              </span>
              <p>
                <strong>2 reachable vulnerabilities</strong>
                <span>Inspector findings prioritized by connectivity</span>
              </p>
            </div>
            <div>
              <span className="signal-icon signal-blue">
                <Radio size={17} />
              </span>
              <p>
                <strong>96% traffic coverage</strong>
                <span>Usage evidence available before cleanup</span>
              </p>
            </div>
            <button
              className="button button-secondary"
              onClick={() => onNavigate("sources")}
            >
              Inspect collection health <ChevronRight size={15} />
            </button>
          </div>
        </section>
      </div>

      <section className="panel review-panel">
        <div className="panel-header">
          <div>
            <h2>Priority review queue</h2>
            <p>
              Ranked by reachability, vulnerability, intent, usage, and
              governance
            </p>
          </div>
          <button
            className="text-button"
            onClick={() => onNavigate("reviews")}
          >
            Open queue <ChevronRight size={14} />
          </button>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Security group</th>
                <th>Primary concern</th>
                <th>Evidence</th>
                <th>Risk</th>
                <th>Status</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {reviewQueue.slice(0, 4).map((group) => (
                <tr key={group.id}>
                  <td>
                    <button
                      className="group-link"
                      onClick={() => onSelect(group)}
                    >
                      <span
                        className={`resource-icon icon-${group.severity}`}
                      >
                        <Network size={17} />
                      </span>
                      <span>
                        <strong>{group.name}</strong>
                        <small>
                          {group.accountName} · {group.region}
                        </small>
                      </span>
                    </button>
                  </td>
                  <td>
                    <span className="finding-cell">
                      <AlertTriangle size={15} /> {group.findings[0]}
                    </span>
                  </td>
                  <td>
                    <div className="mini-evidence">
                      <span title="Confirmed paths">
                        <Route size={13} />
                        {
                          group.paths.filter(
                            (path) => path.status === "reachable",
                          ).length
                        }
                      </span>
                      <span title="Flow Log coverage">
                        <Radio size={13} />
                        {group.traffic.coverage}%
                      </span>
                      <span title="Attached resources">
                        <Box size={13} />
                        {group.attachments.length}
                      </span>
                    </div>
                  </td>
                  <td>
                    <RiskScore
                      score={group.riskScore}
                      projected={group.projectedRisk}
                    />
                  </td>
                  <td>
                    <StatusBadge status={statusFor(group)} />
                  </td>
                  <td>
                    <button
                      className="button button-small"
                      onClick={() => onReview(group)}
                    >
                      Review
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="insight-banner">
        <div className="insight-icon">
          <Sparkles size={20} />
        </div>
        <div>
          <strong>Highest-confidence reduction</strong>
          <p>
            Removing public SSH from prod-payments-api is projected to reduce
            its score from 96 to 41 while preserving the approved load-balancer
            path.
          </p>
        </div>
        <button
          className="button button-dark"
          onClick={() => onSelect(securityGroups[0])}
        >
          Simulate change <ArrowUpRight size={15} />
        </button>
      </section>
    </>
  );
}

function InventoryView({
  groups,
  query,
  setQuery,
  severity,
  setSeverity,
  environment,
  setEnvironment,
  sort,
  setSort,
  onSelect,
  onExport,
  statusFor,
  clearFilters,
}: {
  groups: SecurityGroup[];
  query: string;
  setQuery: (value: string) => void;
  severity: "all" | Severity;
  setSeverity: (value: "all" | Severity) => void;
  environment: string;
  setEnvironment: (value: string) => void;
  sort: string;
  setSort: (value: string) => void;
  onSelect: (group: SecurityGroup) => void;
  onExport: () => void;
  statusFor: (group: SecurityGroup) => ReviewStatus;
  clearFilters: () => void;
}) {
  return (
    <>
      <PageHeader
        eyebrow="Policy findings"
        title="Findings with context"
        description="Every result includes intent, effective paths, usage evidence, change provenance, and a transparent risk calculation."
        actions={
          <button className="button button-primary" onClick={onExport}>
            <Download size={16} /> Export {groups.length} findings
          </button>
        }
      />
      <section className="panel inventory-panel">
        <div className="filter-bar">
          <label className="table-search">
            <Search size={16} />
            <input
              aria-label="Filter findings"
              placeholder="Search finding, group, owner…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <div className="filter-select">
            <SlidersHorizontal size={15} />
            <select
              aria-label="Filter by severity"
              value={severity}
              onChange={(event) =>
                setSeverity(event.target.value as "all" | Severity)
              }
            >
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>
          <div className="filter-select">
            <Filter size={15} />
            <select
              aria-label="Filter by environment"
              value={environment}
              onChange={(event) => setEnvironment(event.target.value)}
            >
              <option value="all">All environments</option>
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
              <option value="shared">Shared</option>
            </select>
          </div>
          <div className="filter-select sort-select">
            <select
              aria-label="Sort findings"
              value={sort}
              onChange={(event) => setSort(event.target.value)}
            >
              <option value="risk">Risk: high to low</option>
              <option value="traffic">Observed traffic</option>
              <option value="name">Name: A–Z</option>
              <option value="changed">Recently changed</option>
            </select>
          </div>
        </div>
        <div className="result-summary">
          <span>
            <strong>{groups.length}</strong> of {securityGroups.length} groups
          </span>
          <span>{policyChecks.length} policy checks · Evaluated 4 min ago</span>
        </div>
        {groups.length ? (
          <div className="table-wrap inventory-table">
            <table>
              <thead>
                <tr>
                  <th>Security group</th>
                  <th>Finding</th>
                  <th>Intent</th>
                  <th>Reachability</th>
                  <th>Traffic</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th>
                    <span className="sr-only">Open</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {groups.map((group) => (
                  <tr
                    key={group.id}
                    onClick={() => onSelect(group)}
                    className="clickable-row"
                  >
                    <td>
                      <div className="group-cell">
                        <span
                          className={`resource-icon icon-${group.severity}`}
                        >
                          <Network size={17} />
                        </span>
                        <span>
                          <strong>{group.name}</strong>
                          <small>
                            {group.id} · {group.accountName}
                          </small>
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className="finding-cell">
                        <AlertTriangle size={14} />{" "}
                        {group.findings[0] ?? "No active finding"}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`intent-chip intent-${group.intent.status}`}
                      >
                        {group.intent.status.replaceAll("-", " ")}
                      </span>
                      <small>{group.intent.ticket}</small>
                    </td>
                    <td>
                      <strong className="cell-primary">
                        {
                          group.paths.filter(
                            (path) => path.status === "reachable",
                          ).length
                        }{" "}
                        confirmed
                      </strong>
                      <small>{group.attachments.length} attached assets</small>
                    </td>
                    <td>
                      <strong className="cell-primary">
                        {group.traffic.accepted30d.toLocaleString()} flows
                      </strong>
                      <small>{group.traffic.coverage}% coverage</small>
                    </td>
                    <td>
                      <RiskScore score={group.riskScore} />
                    </td>
                    <td>
                      <StatusBadge status={statusFor(group)} />
                    </td>
                    <td>
                      <button
                        className="row-open"
                        aria-label={`Investigate ${group.name}`}
                        onClick={(event) => {
                          event.stopPropagation();
                          onSelect(group);
                        }}
                      >
                        <ChevronRight size={17} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">
            <div>
              <Search size={24} />
            </div>
            <h3>No findings match</h3>
            <p>Try a broader search or clear the selected filters.</p>
            <button
              className="button button-secondary"
              onClick={clearFilters}
            >
              Clear filters
            </button>
          </div>
        )}
      </section>
    </>
  );
}

function ConnectivityView({
  onSelect,
  onReview,
}: {
  onSelect: (group: SecurityGroup) => void;
  onReview: (group: SecurityGroup) => void;
}) {
  const [groupId, setGroupId] = useState(securityGroups[0].id);
  const [pathId, setPathId] = useState(securityGroups[0].paths[0].id);
  const group =
    securityGroups.find((item) => item.id === groupId) ?? securityGroups[0];
  const path =
    group.paths.find((item) => item.id === pathId) ?? group.paths[0];

  function selectGroup(nextId: string) {
    const next =
      securityGroups.find((item) => item.id === nextId) ?? securityGroups[0];
    setGroupId(next.id);
    setPathId(next.paths[0].id);
  }

  return (
    <>
      <PageHeader
        eyebrow="Effective connectivity"
        title="Follow the path, not the rule."
        description="Inspect how routes, attachments, security-group references, and observed traffic combine into effective access."
        actions={
          <button
            className="button button-primary"
            onClick={() => onReview(group)}
          >
            <FileCheck2 size={16} /> Review this access
          </button>
        }
      />
      <div className="connectivity-layout">
        <aside className="panel connection-picker">
          <div className="panel-header">
            <div>
              <h2>Investigate group</h2>
              <p>Sorted by current risk</p>
            </div>
          </div>
          <label className="connection-select">
            <span>Security group</span>
            <select
              value={group.id}
              onChange={(event) => selectGroup(event.target.value)}
            >
              {securityGroups.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name} · {item.riskScore}
                </option>
              ))}
            </select>
          </label>
          <div className="path-options" role="list">
            {group.paths.map((item) => (
              <button
                key={item.id}
                className={path.id === item.id ? "active" : ""}
                onClick={() => setPathId(item.id)}
              >
                <span
                  className={`path-status-dot path-status-${item.status}`}
                />
                <span>
                  <strong>
                    {item.source} → {item.destination}
                  </strong>
                  <small>
                    {item.service} · {item.status}
                  </small>
                </span>
                <ChevronRight size={15} />
              </button>
            ))}
          </div>
          <div className="coverage-mini">
            <div>
              <span>Flow coverage</span>
              <strong>{group.traffic.coverage}%</strong>
            </div>
            <div className="coverage-bar">
              <span style={{ width: `${group.traffic.coverage}%` }} />
            </div>
            <p>Last observed {group.traffic.lastObserved}</p>
          </div>
        </aside>

        <section className="panel path-workspace">
          <div className="path-workspace-header">
            <div>
              <div className="title-badges">
                <span className={`path-badge path-${path.status}`}>
                  {path.status}
                </span>
                <span className="confidence-badge">
                  {path.confidence} confidence
                </span>
              </div>
              <h2>{path.service}</h2>
              <p>{path.reason}</p>
            </div>
            <button
              className="button button-secondary"
              onClick={() => onSelect(group)}
            >
              Full evidence <ChevronRight size={15} />
            </button>
          </div>

          <div
            className="path-visual"
            aria-label={`${path.source} to ${path.destination} through ${path.hops.join(
              ", ",
            )}`}
          >
            {path.hops.map((hop, index) => (
              <div className="path-hop-wrap" key={`${hop}-${index}`}>
                <div
                  className={`path-hop ${
                    index === 0 || index === path.hops.length - 1
                      ? "path-hop-edge"
                      : ""
                  }`}
                >
                  <span>
                    {index === 0 ? (
                      <ExternalLink size={17} />
                    ) : index === path.hops.length - 1 ? (
                      <Box size={17} />
                    ) : (
                      <Route size={17} />
                    )}
                  </span>
                  <strong>{hop}</strong>
                  <small>
                    {index === 0
                      ? "Source"
                      : index === path.hops.length - 1
                        ? "Protected asset"
                        : "Network hop"}
                  </small>
                </div>
                {index < path.hops.length - 1 ? (
                  <div className={`path-line path-line-${path.status}`}>
                    <ArrowRight size={17} />
                  </div>
                ) : null}
              </div>
            ))}
          </div>

          <div className="path-evidence-grid">
            <section>
              <div className="section-heading compact">
                <div>
                  <h3>Observed traffic</h3>
                  <p>VPC Flow Logs · last 30 days</p>
                </div>
              </div>
              <div className="traffic-metrics">
                <div>
                  <span>Accepted</span>
                  <strong>{group.traffic.accepted30d.toLocaleString()}</strong>
                </div>
                <div>
                  <span>Rejected</span>
                  <strong>{group.traffic.rejected30d.toLocaleString()}</strong>
                </div>
                <div>
                  <span>Last seen</span>
                  <strong>{group.traffic.lastObserved}</strong>
                </div>
              </div>
              <div className="talker-list">
                {group.traffic.topTalkers.length ? (
                  group.traffic.topTalkers.map((talker) => (
                    <div key={`${talker.source}-${talker.service}`}>
                      <span>
                        <Radio size={13} />
                      </span>
                      <p>
                        <strong>{talker.source}</strong>
                        <small>{talker.service}</small>
                      </p>
                      <em>{talker.flows.toLocaleString()} flows</em>
                    </div>
                  ))
                ) : (
                  <div className="inline-empty">
                    No accepted talkers were observed in the covered period.
                  </div>
                )}
              </div>
            </section>

            <section>
              <div className="section-heading compact">
                <div>
                  <h3>Attached assets</h3>
                  <p>Config resource relationships</p>
                </div>
              </div>
              <div className="asset-list">
                {group.attachments.map((asset) => (
                  <div key={asset.id}>
                    <span className="asset-icon">
                      <Box size={15} />
                    </span>
                    <p>
                      <strong>{asset.name}</strong>
                      <small>
                        {asset.type} · {asset.id}
                      </small>
                    </p>
                    <em className={`asset-${asset.criticality.toLowerCase()}`}>
                      {asset.criticality}
                    </em>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </section>
      </div>
    </>
  );
}

function ReviewQueueView({
  groups,
  statusFor,
  onSelect,
  onReview,
  onExport,
}: {
  groups: SecurityGroup[];
  statusFor: (group: SecurityGroup) => ReviewStatus;
  onSelect: (group: SecurityGroup) => void;
  onReview: (group: SecurityGroup) => void;
  onExport: () => void;
}) {
  return (
    <>
      <PageHeader
        eyebrow="Governance"
        title="Evidence-ready reviews"
        description="Resolve risky access with ownership, intent, usage, change provenance, and expiring exceptions."
        actions={
          <button className="button button-secondary" onClick={onExport}>
            <Download size={16} /> Export queue
          </button>
        }
      />
      <div className="queue-stats">
        <div>
          <span className="queue-icon queue-critical">
            <AlertTriangle size={17} />
          </span>
          <p>
            <strong>
              {
                groups.filter((group) => group.severity === "critical")
                  .length
              }
            </strong>
            <span>Critical priority</span>
          </p>
        </div>
        <div>
          <span className="queue-icon queue-progress">
            <Clock3 size={17} />
          </span>
          <p>
            <strong>
              {
                groups.filter(
                  (group) => statusFor(group) === "in-review",
                ).length
              }
            </strong>
            <span>In progress</span>
          </p>
        </div>
        <div>
          <span className="queue-icon queue-remediate">
            <RefreshCw size={17} />
          </span>
          <p>
            <strong>
              {
                groups.filter(
                  (group) => statusFor(group) === "remediate",
                ).length
              }
            </strong>
            <span>Awaiting remediation</span>
          </p>
        </div>
      </div>
      <section className="queue-list">
        {groups.map((group, index) => (
          <article className="review-card" key={group.id}>
            <div className="review-rank">
              {String(index + 1).padStart(2, "0")}
            </div>
            <div className="review-main">
              <div className="review-title-row">
                <div>
                  <div className="title-badges">
                    <SeverityBadge severity={group.severity} />
                    <StatusBadge status={statusFor(group)} />
                    <span
                      className={`intent-chip intent-${group.intent.status}`}
                    >
                      {group.intent.status.replaceAll("-", " ")}
                    </span>
                  </div>
                  <button onClick={() => onSelect(group)}>
                    {group.name}
                  </button>
                  <p>
                    {group.id} · {group.accountName} · {group.region}
                  </p>
                </div>
                <RiskScore
                  score={group.riskScore}
                  projected={group.projectedRisk}
                />
              </div>
              <div className="review-detail-grid evidence-review-grid">
                <div>
                  <span>Primary concern</span>
                  <strong>
                    <AlertTriangle size={15} /> {group.findings[0]}
                  </strong>
                </div>
                <div>
                  <span>Evidence</span>
                  <strong>
                    <Route size={15} />{" "}
                    {
                      group.paths.filter(
                        (path) => path.status === "reachable",
                      ).length
                    }{" "}
                    paths · {group.traffic.coverage}% flows
                  </strong>
                </div>
                <div>
                  <span>Intent / owner</span>
                  <strong>
                    <Users size={15} /> {group.intent.ticket} · {group.owner}
                  </strong>
                </div>
              </div>
            </div>
            <div className="review-actions">
              <button
                className="button button-secondary"
                onClick={() => onSelect(group)}
              >
                View evidence
              </button>
              <button
                className="button button-primary"
                onClick={() => onReview(group)}
              >
                Record decision <ChevronRight size={15} />
              </button>
            </div>
          </article>
        ))}
        {!groups.length ? (
          <div className="empty-state panel">
            <div>
              <BadgeCheck size={24} />
            </div>
            <h3>Queue cleared</h3>
            <p>All identified security groups have a recorded decision.</p>
          </div>
        ) : null}
      </section>
    </>
  );
}

function ActivityView({
  onSelect,
}: {
  onSelect: (group: SecurityGroup) => void;
}) {
  const [range, setRange] = useState("30");
  const [channel, setChannel] = useState("all");
  const visibleActivity = activity
    .filter((item) => channel === "all" || item.channel === channel)
    .slice(0, range === "7" ? 4 : undefined);

  return (
    <>
      <PageHeader
        eyebrow="CloudTrail provenance"
        title="Change evidence"
        description="See who changed access, through which delivery path, whether approval existed, and exactly what changed."
        actions={
          <>
            <label className="filter-select activity-range">
              <GitPullRequest size={15} />
              <select
                aria-label="Filter by change channel"
                value={channel}
                onChange={(event) => setChannel(event.target.value)}
              >
                <option value="all">All channels</option>
                <option value="Terraform">Terraform</option>
                <option value="Console">Console</option>
                <option value="AWS service">AWS service</option>
                <option value="Automation">Automation</option>
              </select>
            </label>
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
          </>
        }
      />
      <div className="activity-layout">
        <section className="panel activity-panel">
          <div className="panel-header">
            <div>
              <h2>Correlated events</h2>
              <p>CloudTrail API events linked to Config before/after state</p>
            </div>
            <span className="live-chip">
              <span /> Live
            </span>
          </div>
          <div className="change-list">
            {visibleActivity.map((item) => {
              const group = securityGroups.find(
                (candidate) => candidate.id === item.groupId,
              );
              if (!group) return null;
              return (
                <article className="change-card" key={item.eventId}>
                  <span
                    className={`timeline-icon timeline-${item.tone}`}
                  >
                    {item.approved ? (
                      <Check size={16} />
                    ) : (
                      <Activity size={16} />
                    )}
                  </span>
                  <div className="change-main">
                    <div>
                      <span
                        className={`channel-chip channel-${item.channel
                          .toLowerCase()
                          .replace(" ", "-")}`}
                      >
                        {item.channel}
                      </span>
                      {!item.approved ? (
                        <span className="approval-chip">
                          Approval not found
                        </span>
                      ) : null}
                    </div>
                    <button onClick={() => onSelect(group)}>
                      {item.eventName} · {item.group}
                    </button>
                    <p>
                      {item.actor} · {item.sourceIp} · {item.time}
                    </p>
                    <div className="inline-diff">
                      <span>
                        <em>Before</em>
                        {item.before}
                      </span>
                      <ArrowRight size={15} />
                      <span>
                        <em>After</em>
                        {item.after}
                      </span>
                    </div>
                  </div>
                  <code>{item.eventId.slice(0, 8)}</code>
                </article>
              );
            })}
          </div>
        </section>
        <aside className="activity-side">
          <section className="panel event-summary">
            <h2>Change channels</h2>
            <div>
              <span>Terraform</span>
              <strong>42%</strong>
            </div>
            <div>
              <span>AWS services</span>
              <strong>31%</strong>
            </div>
            <div>
              <span>Automation</span>
              <strong>19%</strong>
            </div>
            <div>
              <span>Console</span>
              <strong>8%</strong>
            </div>
          </section>
          <section className="panel source-note">
            <KeyRound size={20} />
            <h3>Evidence integrity</h3>
            <p>
              Every review snapshots the risk score, effective paths, traffic
              coverage, policy intent, and originating CloudTrail event.
            </p>
            <span className="retention-chip">
              <CircleCheck size={13} /> 365-day retention
            </span>
          </section>
        </aside>
      </div>
    </>
  );
}

function SourcesView({
  onSync,
  syncing,
}: {
  onSync: () => void;
  syncing: boolean;
}) {
  const sources = [
    {
      name: "AWS Config aggregator",
      detail: "Inventory, history, and resource relationships",
      status: "Healthy",
      coverage: "100%",
      time: "4 min ago",
      icon: Database,
    },
    {
      name: "CloudTrail Lake",
      detail: "Security-group management events and caller identity",
      status: "Healthy",
      coverage: "100%",
      time: "2 min ago",
      icon: Activity,
    },
    {
      name: "VPC Flow Logs",
      detail: "Accepted and rejected traffic for attached ENIs",
      status: "Partial",
      coverage: "92%",
      time: "6 min ago",
      icon: Radio,
    },
    {
      name: "Inspector + Security Hub",
      detail: "Vulnerability and asset-criticality context",
      status: "Healthy",
      coverage: "97%",
      time: "11 min ago",
      icon: ShieldAlert,
    },
    {
      name: "Terraform access manifests",
      detail: "Approved application connectivity and ticket intent",
      status: "Partial",
      coverage: "78%",
      time: "18 min ago",
      icon: Braces,
    },
  ];
  return (
    <>
      <PageHeader
        eyebrow="Evidence pipeline"
        title="Data coverage"
        description="Understand which evidence supports each finding and where incomplete coverage limits confidence."
        actions={
          <button
            className="button button-primary"
            onClick={onSync}
            disabled={syncing}
          >
            <RefreshCw size={16} className={syncing ? "spin" : ""} />
            {syncing ? "Refreshing…" : "Refresh all sources"}
          </button>
        }
      />
      <section className="source-health-banner">
        <span>
          <CircleCheck size={21} />
        </span>
        <div>
          <strong>Core AWS evidence is healthy</strong>
          <p>
            Flow Log coverage and application intent remain incomplete in two
            development accounts; affected findings are marked lower
            confidence.
          </p>
        </div>
        <em>96% weighted coverage</em>
      </section>
      <section className="panel sources-panel">
        <div className="panel-header">
          <div>
            <h2>Connected sources</h2>
            <p>Read-only collection and policy-as-code inputs</p>
          </div>
          <button
            className="button button-secondary"
            disabled
            title="Connection editing requires AWS administrator credentials"
          >
            <Settings size={15} /> Connection settings
          </button>
        </div>
        <div className="source-list">
          {sources.map((source) => {
            const Icon = source.icon;
            return (
              <div className="source-row source-row-rich" key={source.name}>
                <span className="source-icon">
                  <Icon size={19} />
                </span>
                <div>
                  <strong>{source.name}</strong>
                  <p>{source.detail}</p>
                </div>
                <span
                  className={`source-status ${
                    source.status === "Partial" ? "source-partial" : ""
                  }`}
                >
                  <i /> {source.status}
                </span>
                <div className="source-coverage">
                  <strong>{source.coverage}</strong>
                  <small>coverage</small>
                </div>
                <time>Synced {source.time}</time>
              </div>
            );
          })}
        </div>
      </section>
      <div className="source-detail-grid">
        <section className="panel collection-panel">
          <div>
            <span className="collection-icon">
              <CloudCog size={20} />
            </span>
            <h2>Collection scope</h2>
          </div>
          <div className="scope-grid">
            <div>
              <span>AWS accounts</span>
              <strong>6 connected</strong>
              <small>Organization aggregator</small>
            </div>
            <div>
              <span>Regions</span>
              <strong>4 enabled</strong>
              <small>Future regions included</small>
            </div>
            <div>
              <span>Evaluation</span>
              <strong>Every 15 min</strong>
              <small>Event refresh enabled</small>
            </div>
          </div>
        </section>
        <section className="panel policy-pack-panel">
          <div className="panel-header">
            <div>
              <h2>Active policy pack</h2>
              <p>{policyChecks.length} explainable checks</p>
            </div>
            <span className="version-chip">v1.4</span>
          </div>
          <div className="policy-checks">
            {policyChecks.slice(0, 6).map((check) => (
              <span key={check}>
                <Check size={12} /> {check}
              </span>
            ))}
            <em>+{policyChecks.length - 6} more</em>
          </div>
        </section>
      </div>
    </>
  );
}

function GroupDrawer({
  group,
  status,
  review,
  onClose,
  onReview,
}: {
  group: SecurityGroup;
  status: ReviewStatus;
  review?: ReviewRecord;
  onClose: () => void;
  onReview: () => void;
}) {
  const [tab, setTab] = useState<DrawerTab>("evidence");
  const [simulation, setSimulation] = useState(false);

  return (
    <div
      className="drawer-layer"
      role="dialog"
      aria-modal="true"
      aria-labelledby="drawer-title"
    >
      <button
        className="drawer-scrim"
        aria-label="Close details"
        onClick={onClose}
      />
      <aside className="group-drawer evidence-drawer">
        <div className="drawer-header">
          <div>
            <p>Security group investigation</p>
            <h2 id="drawer-title">{group.name}</h2>
            <span>
              {group.id} · {group.accountName} · {group.region}
            </span>
          </div>
          <button
            className="icon-button"
            aria-label="Close details"
            onClick={onClose}
          >
            <X size={18} />
          </button>
        </div>
        <div className="drawer-risk">
          <div
            className={`score-ring score-${riskTone(
              simulation ? group.projectedRisk : group.riskScore,
            )}`}
          >
            <strong>
              {simulation ? group.projectedRisk : group.riskScore}
            </strong>
            <span>{simulation ? "projected" : "risk"}</span>
          </div>
          <div>
            <div className="title-badges">
              <SeverityBadge severity={group.severity} />
              <StatusBadge status={status} />
              <span
                className={`intent-chip intent-${group.intent.status}`}
              >
                {group.intent.status.replaceAll("-", " ")}
              </span>
            </div>
            <p>
              {simulation
                ? `${group.riskScore - group.projectedRisk} points removed while preserving intended access`
                : `${group.findings.length} evidence-backed findings`}
            </p>
          </div>
          <button className="button button-primary" onClick={onReview}>
            Record review
          </button>
        </div>
        <div className="drawer-tabs" role="tablist">
          {(
            [
              ["evidence", "Evidence"],
              ["connectivity", "Connectivity"],
              ["change", "Change diff"],
              ["risk", "Risk model"],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              className={tab === value ? "active" : ""}
              role="tab"
              aria-selected={tab === value}
              onClick={() => setTab(value)}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="drawer-body">
          {tab === "evidence" ? (
            <>
              <section className="detail-grid">
                <div>
                  <span>Application</span>
                  <strong>{group.intent.application}</strong>
                  <small>{group.intent.ticket}</small>
                </div>
                <div>
                  <span>Owner</span>
                  <strong>{group.owner}</strong>
                  <small>{group.service}</small>
                </div>
                <div>
                  <span>Attached assets</span>
                  <strong>{group.attachments.length}</strong>
                  <small>
                    {group.attachments
                      .map((asset) => asset.type)
                      .join(", ")}
                  </small>
                </div>
                <div>
                  <span>Traffic coverage</span>
                  <strong>{group.traffic.coverage}%</strong>
                  <small>Last seen {group.traffic.lastObserved}</small>
                </div>
              </section>

              <section className="intent-card">
                <div className="section-heading compact">
                  <div>
                    <h3>Approved intent</h3>
                    <p>
                      {group.intent.ticket} · {group.intent.owner}
                    </p>
                  </div>
                  <span
                    className={`intent-chip intent-${group.intent.status}`}
                  >
                    {group.intent.status.replaceAll("-", " ")}
                  </span>
                </div>
                <strong>{group.intent.approvedAccess}</strong>
                <p>{group.intent.justification}</p>
                {group.intent.expiresAt ? (
                  <em>
                    <Clock3 size={13} /> Expires {group.intent.expiresAt}
                  </em>
                ) : null}
              </section>

              {group.findings.length ? (
                <section className="findings-box">
                  <div className="findings-title">
                    <AlertTriangle size={17} />
                    <strong>Why this needs attention</strong>
                  </div>
                  {group.findings.map((finding) => (
                    <div className="finding-row" key={finding}>
                      <span />
                      <p>{finding}</p>
                    </div>
                  ))}
                </section>
              ) : (
                <section className="aligned-banner">
                  <CircleCheck size={18} />
                  <div>
                    <strong>Actual access matches approved intent</strong>
                    <p>Continuous monitoring remains active for drift.</p>
                  </div>
                </section>
              )}

              <section className="rules-section">
                <div className="section-heading">
                  <div>
                    <h3>Effective rules</h3>
                    <p>
                      {group.inboundCount} ingress · {group.outboundCount}{" "}
                      egress · AWS Config
                    </p>
                  </div>
                </div>
                <div className="rule-list">
                  {group.rules.map((rule) => (
                    <div className="rule-row rule-row-evidence" key={rule.id}>
                      <span
                        className={`direction-icon direction-${rule.direction.toLowerCase()}`}
                      >
                        {rule.direction === "Ingress" ? (
                          <ArrowDownToLine size={15} />
                        ) : (
                          <ArrowUpRight size={15} />
                        )}
                      </span>
                      <div className="rule-main">
                        <div>
                          <strong>{rule.direction}</strong>
                          <span>
                            {rule.protocol} · {rule.ports}
                          </span>
                        </div>
                        <p>
                          {rule.sourceLabel}
                          <code>{rule.source}</code>
                        </p>
                        <div className="rule-usage">
                          <Radio size={11} />{" "}
                          {rule.flows30d.toLocaleString()} flows · Last seen{" "}
                          {rule.lastObserved}
                        </div>
                        {rule.finding ? (
                          <em>
                            <AlertTriangle size={12} /> {rule.finding}
                          </em>
                        ) : null}
                      </div>
                      <span
                        className={`exposure exposure-${rule.exposure.toLowerCase()}`}
                      >
                        {rule.exposure}
                      </span>
                    </div>
                  ))}
                </div>
              </section>

              {review?.note ? (
                <section className="review-note">
                  <span>
                    <FileCheck2 size={17} />
                  </span>
                  <div>
                    <strong>Latest review decision</strong>
                    <p>{review.note}</p>
                    <small>
                      Reviewed by {review.reviewer ?? review.assignee} ·{" "}
                      {review.ticketRef} ·{" "}
                      {review.updatedAt ?? "Recently"}
                    </small>
                  </div>
                </section>
              ) : null}
            </>
          ) : null}

          {tab === "connectivity" ? (
            <>
              <section className="drawer-section-intro">
                <h3>Effective network paths</h3>
                <p>
                  Security groups, routes, gateways, attachments, and Flow
                  Logs evaluated together.
                </p>
              </section>
              <div className="drawer-path-list">
                {group.paths.map((path) => (
                  <article key={path.id}>
                    <div>
                      <span className={`path-badge path-${path.status}`}>
                        {path.status}
                      </span>
                      <span className="confidence-badge">
                        {path.confidence} confidence
                      </span>
                    </div>
                    <h4>
                      {path.source} <ArrowRight size={14} />{" "}
                      {path.destination}
                    </h4>
                    <strong>{path.service}</strong>
                    <p>{path.reason}</p>
                    <div className="compact-hop-list">
                      {path.hops.map((hop, index) => (
                        <span key={`${hop}-${index}`}>
                          {hop}
                          {index < path.hops.length - 1 ? (
                            <ChevronRight size={12} />
                          ) : null}
                        </span>
                      ))}
                    </div>
                  </article>
                ))}
              </div>
              <section className="drawer-assets">
                <div className="section-heading compact">
                  <div>
                    <h3>Resource attachments</h3>
                    <p>Config relationship graph</p>
                  </div>
                </div>
                <div className="asset-list">
                  {group.attachments.map((asset) => (
                    <div key={asset.id}>
                      <span className="asset-icon">
                        <Box size={15} />
                      </span>
                      <p>
                        <strong>{asset.name}</strong>
                        <small>
                          {asset.type} · {asset.id}
                        </small>
                      </p>
                      <em
                        className={`asset-${asset.criticality.toLowerCase()}`}
                      >
                        {asset.criticality}
                      </em>
                    </div>
                  ))}
                </div>
              </section>
            </>
          ) : null}

          {tab === "change" ? (
            <>
              <section className="change-evidence-hero">
                <span
                  className={`change-approval ${
                    group.change.approved ? "approved" : "unapproved"
                  }`}
                >
                  {group.change.approved ? (
                    <Check size={14} />
                  ) : (
                    <CircleAlert size={14} />
                  )}
                  {group.change.approved
                    ? "Approved workflow"
                    : "Approval not found"}
                </span>
                <h3>{group.change.eventName}</h3>
                <p>
                  {group.change.actor} · {group.change.channel} ·{" "}
                  {group.change.time}
                </p>
              </section>
              <section className="change-metadata">
                <div>
                  <span>CloudTrail event ID</span>
                  <code>{group.change.eventId}</code>
                </div>
                <div>
                  <span>Source address</span>
                  <strong>{group.change.sourceIp}</strong>
                </div>
                <div>
                  <span>Delivery channel</span>
                  <strong>{group.change.channel}</strong>
                </div>
              </section>
              <section className="change-diff">
                <div>
                  <span>Before</span>
                  <code>- {group.change.before}</code>
                </div>
                <div>
                  <span>After</span>
                  <code>+ {group.change.after}</code>
                </div>
              </section>
              <section className="intent-card">
                <div className="section-heading compact">
                  <div>
                    <h3>Intent comparison</h3>
                    <p>{group.intent.ticket}</p>
                  </div>
                  <span
                    className={`intent-chip intent-${group.intent.status}`}
                  >
                    {group.intent.status.replaceAll("-", " ")}
                  </span>
                </div>
                <strong>{group.intent.approvedAccess}</strong>
                <p>{group.intent.justification}</p>
              </section>
            </>
          ) : null}

          {tab === "risk" ? (
            <>
              <section className="risk-explainer">
                <div>
                  <h3>Explainable risk calculation</h3>
                  <p>
                    Every point is attributable to collected evidence. This is
                    not a black-box score.
                  </p>
                </div>
                <RiskScore
                  score={group.riskScore}
                  projected={
                    simulation ? group.projectedRisk : undefined
                  }
                />
              </section>
              <div className="risk-factor-list">
                {group.riskFactors.map((factor) => {
                  const projectedPoints =
                    simulation &&
                    ["reachability", "intent", "usage"].includes(factor.key)
                      ? Math.max(
                          0,
                          Math.round(
                            factor.points *
                              (group.projectedRisk / group.riskScore),
                          ),
                        )
                      : factor.points;
                  return (
                    <article key={factor.key}>
                      <div>
                        <strong>{factor.label}</strong>
                        <span>
                          {projectedPoints}/{factor.maxPoints} points
                        </span>
                      </div>
                      <div className="factor-track">
                        <span
                          style={{
                            width: `${Math.min(
                              100,
                              (projectedPoints / factor.maxPoints) * 100,
                            )}%`,
                          }}
                        />
                      </div>
                      <p>{factor.evidence}</p>
                    </article>
                  );
                })}
              </div>

              {group.vulnerabilities.length ? (
                <section className="vulnerability-list">
                  <div className="section-heading compact">
                    <div>
                      <h3>Reachability-prioritized vulnerabilities</h3>
                      <p>Inspector and Security Hub context</p>
                    </div>
                  </div>
                  {group.vulnerabilities.map((finding) => (
                    <div key={finding.resource}>
                      <span
                        className={`vuln-icon icon-${finding.highestSeverity}`}
                      >
                        <ShieldAlert size={15} />
                      </span>
                      <p>
                        <strong>{finding.resource}</strong>
                        <small>{finding.summary}</small>
                      </p>
                      <em>
                        {finding.cves} finding
                        {finding.cves === 1 ? "" : "s"}
                      </em>
                    </div>
                  ))}
                </section>
              ) : (
                <section className="aligned-banner">
                  <CircleCheck size={18} />
                  <div>
                    <strong>No active vulnerability context</strong>
                    <p>
                      Inspector coverage is available for the attached assets.
                    </p>
                  </div>
                </section>
              )}

              <section
                className={`simulation-card ${
                  simulation ? "simulation-active" : ""
                }`}
              >
                <div>
                  <span>
                    <Sparkles size={16} /> Read-only simulation
                  </span>
                  <h3>{group.recommendation}</h3>
                  <p>
                    No AWS change will be made. Gatewatch recomputes risk using
                    the proposed policy state.
                  </p>
                </div>
                <button
                  className={`button ${
                    simulation ? "button-secondary" : "button-dark"
                  }`}
                  onClick={() => setSimulation((current) => !current)}
                >
                  {simulation ? "Reset simulation" : "Simulate remediation"}
                </button>
              </section>
            </>
          ) : null}
        </div>
      </aside>
    </div>
  );
}

function ReviewModal({
  group,
  status,
  setStatus,
  assignee,
  setAssignee,
  note,
  setNote,
  ticket,
  setTicket,
  expiry,
  setExpiry,
  error,
  saving,
  onClose,
  onSave,
}: {
  group: SecurityGroup;
  status: ReviewStatus;
  setStatus: (value: ReviewStatus) => void;
  assignee: string;
  setAssignee: (value: string) => void;
  note: string;
  setNote: (value: string) => void;
  ticket: string;
  setTicket: (value: string) => void;
  expiry: string;
  setExpiry: (value: string) => void;
  error: string;
  saving: boolean;
  onClose: () => void;
  onSave: () => void;
}) {
  return (
    <div
      className="modal-layer"
      role="dialog"
      aria-modal="true"
      aria-labelledby="review-title"
    >
      <button
        className="modal-scrim"
        aria-label="Close review"
        onClick={onClose}
      />
      <div className="review-modal evidence-review-modal">
        <div className="modal-header">
          <div>
            <p>Evidence-backed review</p>
            <h2 id="review-title">{group.name}</h2>
            <span>
              {group.id} · Risk {group.riskScore} ·{" "}
              {
                group.paths.filter(
                  (path) => path.status === "reachable",
                ).length
              }{" "}
              confirmed paths
            </span>
          </div>
          <button
            className="icon-button"
            aria-label="Close review"
            onClick={onClose}
          >
            <X size={18} />
          </button>
        </div>
        <div className="modal-body">
          <div className="review-warning">
            <AlertTriangle size={17} />
            <p>
              <strong>{group.findings[0]}</strong>
              <span>
                {group.traffic.accepted30d.toLocaleString()} observed flows ·{" "}
                {group.traffic.coverage}% coverage · Intent{" "}
                {group.intent.status.replaceAll("-", " ")}
              </span>
            </p>
          </div>
          <fieldset className="decision-fieldset">
            <legend>Decision</legend>
            <div className="decision-grid">
              {(
                [
                  ["in-review", "Continue review", Clock3],
                  ["approved", "Approve access", BadgeCheck],
                  ["remediate", "Request fix", RefreshCw],
                  ["exception", "Accept exception", ShieldEllipsis],
                ] as const
              ).map(([value, label, Icon]) => (
                <label
                  className={status === value ? "selected" : ""}
                  key={value}
                >
                  <input
                    type="radio"
                    name="decision"
                    value={value}
                    checked={status === value}
                    onChange={() => setStatus(value)}
                  />
                  <Icon size={17} />
                  <span>{label}</span>
                  <Check size={15} className="decision-check" />
                </label>
              ))}
            </div>
          </fieldset>
          <div className="form-grid-two">
            <label className="form-field">
              <span>Assignee</span>
              <div className="input-with-icon">
                <UserRound size={16} />
                <select
                  value={assignee}
                  onChange={(event) => setAssignee(event.target.value)}
                >
                  <option>Morgan Lee</option>
                  <option>Payments Platform</option>
                  <option>Cloud Operations</option>
                  <option>Data Reliability</option>
                  <option>Analytics Engineering</option>
                  <option>Commerce Runtime</option>
                </select>
              </div>
            </label>
            <label className="form-field">
              <span>
                Ticket or pull request{" "}
                {status === "in-review" ? <em>Optional</em> : <em>Required</em>}
              </span>
              <div className="input-with-icon">
                <GitPullRequest size={16} />
                <input
                  value={ticket}
                  onChange={(event) => setTicket(event.target.value)}
                  maxLength={120}
                  placeholder="SEC-1234"
                />
              </div>
            </label>
          </div>
          {status === "exception" ? (
            <label className="form-field">
              <span>
                Exception expires <em>Required</em>
              </span>
              <div className="input-with-icon">
                <Clock3 size={16} />
                <input
                  type="date"
                  value={expiry}
                  min={new Date().toISOString().slice(0, 10)}
                  onChange={(event) => setExpiry(event.target.value)}
                />
              </div>
            </label>
          ) : null}
          <label className="form-field">
            <span>
              Decision rationale{" "}
              {status === "in-review" ? <em>Optional</em> : <em>Required</em>}
            </span>
            <textarea
              value={note}
              onChange={(event) => setNote(event.target.value)}
              maxLength={1200}
              placeholder="Document the business justification, evidence considered, compensating controls, or required remediation…"
            />
            <small>{note.length}/1200</small>
          </label>
          <div className="snapshot-note">
            <FileCheck2 size={15} />
            <p>
              <strong>Evidence snapshot included</strong>
              <span>
                Risk model, effective paths, 30-day traffic, intent status, and
                CloudTrail event ID will be stored with this decision.
              </span>
            </p>
          </div>
          {error ? (
            <div className="form-error" role="alert">
              <CircleAlert size={15} /> {error}
            </div>
          ) : null}
        </div>
        <div className="modal-footer">
          <button className="button button-secondary" onClick={onClose}>
            Cancel
          </button>
          <button
            className="button button-primary"
            onClick={onSave}
            disabled={saving}
          >
            {saving ? (
              <>
                <RefreshCw size={15} className="spin" /> Saving…
              </>
            ) : (
              <>
                Save decision <ChevronRight size={15} />
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
