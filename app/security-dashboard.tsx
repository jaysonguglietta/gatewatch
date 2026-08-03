"use client";

import {
  Activity,
  AlertTriangle,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  BadgeCheck,
  Bell,
  BookOpenCheck,
  Box,
  Braces,
  CalendarCheck2,
  Check,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Clock3,
  CloudCog,
  Crown,
  Database,
  Download,
  ExternalLink,
  Eye,
  FileCheck2,
  FileArchive,
  FileCode2,
  FileJson2,
  FileBarChart,
  Filter,
  Gauge,
  GitPullRequest,
  History,
  KeyRound,
  Menu,
  Network,
  Radio,
  RefreshCw,
  Route,
  Search,
  Save,
  Settings,
  ShieldAlert,
  ShieldCheck,
  ShieldEllipsis,
  SlidersHorizontal,
  Sparkles,
  Target,
  Trash2,
  UploadCloud,
  UserRound,
  Users,
  X,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  policyChecks,
  securityGroups,
  type ReviewStatus,
  type SecurityRule,
  type SecurityGroup,
  type Severity,
  weeklyExposure,
  weeklyLabels,
} from "../lib/security-data";
import {
  canonicalSecurityGroupKey,
  canonicalFindingFingerprint,
  evidenceForGroup,
  evidenceSnapshotJson,
} from "../lib/evidence-model";
import {
  accessQueryExamples,
  accessScopes,
  applications,
  awsHandoffs,
  campaigns,
  connectivityEvents,
  remediations,
  type AccessScope,
  type Campaign,
} from "../lib/governance-data";
import {
  parseCloudTrailText,
  readCloudTrailFile,
  type CloudTrailImportResult,
  type ImportedCloudTrailEvent,
} from "../lib/cloudtrail-import";
import { csvDocument } from "../lib/csv";
import AdminView from "./admin-view";
import DailyFindingsView from "./daily-findings-view";
import ReportingView from "./reporting-view";
import OrganizationCoveragePanel from "./organization-coverage-panel";
import {
  DriftInboxView,
  ExposureIntelligenceView,
  OwnerGovernanceView,
  RecommendationCenterView,
} from "./product-intelligence";

type View =
  | "overview"
  | "access"
  | "inventory"
  | "connectivity"
  | "reviews"
  | "policies"
  | "applications"
  | "campaigns"
  | "remediation"
  | "cloudtrail"
  | "handoffs"
  | "activity"
  | "sources"
  | "admin"
  | "exposure"
  | "recommendations"
  | "drift"
  | "ownership"
  | "metrics";

type DrawerTab = "evidence" | "connectivity" | "change" | "risk";

type ReviewRecord = {
  resourceKey?: string;
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

type CloudTrailSessionImport = {
  fileName: string;
  fileSize: number;
  importedAt: string;
  result: CloudTrailImportResult;
};

type AwsInventorySource = {
  mode: "aws";
  snapshotId: string;
  generatedAt: string;
  complete: boolean;
  accountCount: number;
  accountsExpected: number;
  regionCount: number;
  regionsExpected: number;
  groupCount: number;
  ruleCount: number;
  errorCount: number;
  coveragePercent: number;
  freshnessMinutes: number;
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

function downloadText(filename: string, content: string, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export default function SecurityDashboard() {
  const [view, setView] = useState<View>("inventory");
  const [query, setQuery] = useState("");
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
  const [inventorySource, setInventorySource] =
    useState<AwsInventorySource | null>(null);
  const [, setInventoryRevision] = useState(0);
  const [cloudTrailImport, setCloudTrailImport] =
    useState<CloudTrailSessionImport | null>(null);
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
              review.resourceKey ?? review.securityGroupId,
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

  const refreshInventory = useCallback(
    async (force: boolean, notify: boolean) => {
      setSyncing(true);
      try {
        const response = await fetch(
          `/api/aws-inventory${force ? "?refresh=true" : ""}`,
          { cache: "no-store" },
        );
        const payload = (await response.json()) as {
          groups?: SecurityGroup[];
          source?: AwsInventorySource;
          error?: string;
        };
        if (!response.ok || !payload.groups || !payload.source) {
          throw new Error(
            payload.error ?? "The AWS security-group inventory is unavailable.",
          );
        }
        securityGroups.splice(0, securityGroups.length, ...payload.groups);
        setInventorySource(payload.source);
        setInventoryRevision((current) => current + 1);
        if (notify) {
          setToast(
            `Loaded ${payload.source.groupCount} security groups and ${payload.source.ruleCount} rules from AWS.`,
          );
        }
      } catch (error) {
        if (notify) {
          setToast(
            error instanceof Error
              ? error.message
              : "The AWS security-group inventory is unavailable.",
          );
        }
      } finally {
        setSyncing(false);
      }
    },
    [],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void refreshInventory(false, false);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [refreshInventory]);

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

  const reviewFor = (group: SecurityGroup) =>
    reviewOverrides[canonicalSecurityGroupKey(group)] ?? reviewOverrides[group.id];

  const statusFor = (group: SecurityGroup) =>
    reviewFor(group)?.status ?? group.defaultStatus;

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
    const existing = reviewFor(group);
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
      const resourceKey = canonicalSecurityGroupKey(reviewTarget);
      const evidenceSnapshot = evidenceSnapshotJson(
        reviewTarget,
        evidenceForGroup(
          reviewTarget,
          inventorySource?.snapshotId ?? reviewTarget.change.eventId,
          inventorySource?.generatedAt ?? reviewTarget.change.time,
        ),
      );
      const response = await fetch("/api/reviews", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          resourceKey,
          securityGroupId: reviewTarget.id,
          accountId: reviewTarget.accountId,
          region: reviewTarget.region,
          vpcId: reviewTarget.vpc,
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
        [payload.review!.resourceKey ?? resourceKey]: payload.review as ReviewRecord,
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
    const csv = csvDocument([headers, ...rows]);
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
    void refreshInventory(true, true);
  }

  const navigationGroups = [
    {
      id: "findings",
      label: "Findings",
      icon: ShieldAlert,
      items: [
        { id: "inventory" as View, label: "Daily findings", icon: FileCheck2 },
        { id: "overview" as View, label: "Broad access", icon: Gauge },
        { id: "exposure" as View, label: "Exposure intelligence", icon: Zap },
        { id: "drift" as View, label: "Drift inbox", icon: AlertTriangle },
        { id: "recommendations" as View, label: "Recommendations", icon: Sparkles },
      ],
    },
    {
      id: "inventory",
      label: "Inventory",
      icon: Database,
      items: [
        { id: "access" as View, label: "Access explorer", icon: Search },
        { id: "connectivity" as View, label: "Path evidence", icon: Route },
        { id: "activity" as View, label: "Connectivity history", icon: History },
        { id: "sources" as View, label: "Organization coverage", icon: CloudCog },
      ],
    },
    {
      id: "governance",
      label: "Governance",
      icon: BookOpenCheck,
      items: [
        { id: "applications" as View, label: "Applications", icon: Crown },
        { id: "ownership" as View, label: "Owner governance", icon: Users },
        { id: "policies" as View, label: "Access policies", icon: BookOpenCheck },
        { id: "reviews" as View, label: "Review queue", icon: FileCheck2, count: reviewQueue.length },
        { id: "campaigns" as View, label: "Campaigns", icon: CalendarCheck2 },
        { id: "remediation" as View, label: "Remediation", icon: Target },
      ],
    },
    {
      id: "reports",
      label: "Reports",
      icon: FileBarChart,
      items: [
        { id: "metrics" as View, label: "Detailed reports", icon: FileBarChart },
        { id: "cloudtrail" as View, label: "CloudTrail imports", icon: UploadCloud },
        { id: "handoffs" as View, label: "AWS handoffs", icon: FileCode2 },
      ],
    },
    {
      id: "administration",
      label: "Administration",
      icon: Settings,
      items: [{ id: "admin" as View, label: "Admin configuration", icon: Settings }],
    },
  ];
  const activeNavigationGroup = navigationGroups.find((group) =>
    group.items.some((item) => item.id === view),
  ) ?? navigationGroups[0];

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
            <span>Access governance</span>
          </div>
        </div>

        <nav className="primary-nav">
          <p className="nav-label">Workspace</p>
          {navigationGroups.map((group) => {
            const Icon = group.icon;
            return (
              <div className="nav-workspace-group" key={group.id}>
                <button className={activeNavigationGroup.id === group.id ? "active workspace-active" : ""} onClick={() => navigate(group.items[0].id)} aria-expanded={activeNavigationGroup.id === group.id}>
                  <Icon size={18} /><span>{group.label}</span><ChevronRight size={14} />
                </button>
                {activeNavigationGroup.id === group.id ? <div className="nav-context-items">{group.items.map((item) => {
                  const ItemIcon = item.icon;
                  return <button key={item.id} className={view === item.id ? "active" : ""} onClick={() => navigate(item.id)}><ItemIcon size={15} /><span>{item.label}</span>{"count" in item && item.count ? <em>{item.count}</em> : null}</button>;
                })}</div> : null}
              </div>
            );
          })}
        </nav>

        <div className="coverage-card">
          <div className="coverage-heading">
            <span>
              <Radio size={15} /> Evidence coverage
            </span>
            <strong>{inventorySource ? `${inventorySource.coveragePercent}%` : "—"}</strong>
          </div>
          <div className="progress-track">
            <span style={{ width: `${inventorySource?.coveragePercent ?? 0}%` }} />
          </div>
          <p>
            {inventorySource
              ? `${inventorySource.accountCount}/${inventorySource.accountsExpected} accounts · ${inventorySource.regionCount}/${inventorySource.regionsExpected} regions · ${inventorySource.freshnessMinutes}m old`
              : "Loading AWS evidence coverage…"}
          </p>
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
              placeholder="Search groups, CIDRs, findings, owners…"
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
                <strong>{inventorySource ? "AWS evidence current" : "Loading AWS evidence"}</strong>
                <small>
                  {inventorySource
                    ? `${inventorySource.groupCount} groups · ${inventorySource.ruleCount} rules`
                    : "Connecting to the encrypted snapshot"}
                </small>
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
            <DailyFindingsView
              globalQuery={query || undefined}
              onGlobalQueryChange={setQuery}
              onOpenGroup={(securityGroupId) => {
                const group = securityGroups.find(
                  (item) => item.id === securityGroupId,
                );
                if (group) setSelectedGroup(group);
              }}
              onToast={setToast}
            />
          ) : null}
          {view === "access" ? (
            <AccessExplorerView
              onSelect={setSelectedGroup}
              onReview={openReview}
              onToast={setToast}
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
          {view === "applications" ? (
            <ApplicationsView
              onSelect={setSelectedGroup}
              onNavigate={navigate}
            />
          ) : null}
          {view === "policies" ? (
            <PoliciesView onToast={setToast} />
          ) : null}
          {view === "campaigns" ? (
            <CampaignsView
              onToast={setToast}
              onNavigate={navigate}
            />
          ) : null}
          {view === "remediation" ? (
            <RemediationView
              onSelect={setSelectedGroup}
              onToast={setToast}
              onNavigate={navigate}
            />
          ) : null}
          {view === "cloudtrail" ? (
            <CloudTrailImportView
              imported={cloudTrailImport}
              setImported={setCloudTrailImport}
              onSelect={setSelectedGroup}
              onToast={setToast}
            />
          ) : null}
          {view === "handoffs" ? (
            <HandoffsView onToast={setToast} />
          ) : null}
          {view === "activity" ? (
            <ActivityView onSelect={setSelectedGroup} />
          ) : null}
          {view === "sources" ? (
            <SourcesView onSync={syncNow} syncing={syncing} inventorySource={inventorySource} />
          ) : null}
          {view === "admin" ? <AdminView onToast={setToast} /> : null}
          {view === "exposure" ? (
            <ExposureIntelligenceView onToast={setToast} />
          ) : null}
          {view === "recommendations" ? (
            <RecommendationCenterView onToast={setToast} />
          ) : null}
          {view === "drift" ? <DriftInboxView onToast={setToast} /> : null}
          {view === "ownership" ? (
            <OwnerGovernanceView onToast={setToast} />
          ) : null}
          {view === "metrics" ? (
            <ReportingView onToast={setToast} />
          ) : null}
        </div>
      </main>

      {selectedGroup ? (
        <GroupDrawer
          group={selectedGroup}
          status={statusFor(selectedGroup)}
          review={reviewFor(selectedGroup)}
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

type BroadRule = {
  group: SecurityGroup;
  rule: SecurityRule;
  category: "Internet-wide" | "All traffic" | "Broad CIDR" | "Wide port range";
  reason: string;
};

function broadRuleClassification(rule: SecurityRule) {
  if (rule.source === "0.0.0.0/0" || rule.source === "::/0") {
    return {
      category: "Internet-wide" as const,
      reason:
        rule.direction === "Ingress"
          ? "Any internet address can initiate traffic"
          : "Traffic can be sent to any internet address",
    };
  }
  if (rule.protocol === "All" || rule.ports === "All") {
    return {
      category: "All traffic" as const,
      reason: "The rule does not restrict protocol or port",
    };
  }
  const cidrPrefix = rule.source.match(/\/(\d{1,2})$/)?.[1];
  if (cidrPrefix && Number(cidrPrefix) <= 16) {
    return {
      category: "Broad CIDR" as const,
      reason: `The /${cidrPrefix} network contains a large address range`,
    };
  }
  const portRange = rule.ports.match(/^(\d+)[–-](\d+)$/);
  if (portRange && Number(portRange[2]) - Number(portRange[1]) >= 100) {
    return {
      category: "Wide port range" as const,
      reason: `${Number(portRange[2]) - Number(portRange[1]) + 1} ports are allowed`,
    };
  }
  return null;
}

const broadRules: BroadRule[] = securityGroups.flatMap((group) =>
  group.rules.flatMap((rule) => {
    const classification = broadRuleClassification(rule);
    return classification ? [{ group, rule, ...classification }] : [];
  }),
);

function BroadRulesPanel({
  onSelect,
  onReview,
}: {
  onSelect: (group: SecurityGroup) => void;
  onReview: (group: SecurityGroup) => void;
}) {
  const [direction, setDirection] = useState<"all" | "Ingress" | "Egress">(
    "all",
  );
  const [category, setCategory] = useState("all");
  const [ruleQuery, setRuleQuery] = useState("");
  const filtered = broadRules.filter((item) => {
    const searchable = [
      item.group.name,
      item.group.id,
      item.group.accountName,
      item.group.owner,
      item.rule.source,
      item.rule.ports,
      item.category,
    ]
      .join(" ")
      .toLowerCase();
    return (
      (direction === "all" || item.rule.direction === direction) &&
      (category === "all" || item.category === category) &&
      (!ruleQuery || searchable.includes(ruleQuery.toLowerCase()))
    );
  });

  function exportRules() {
    const rows = [
      [
        "Security group",
        "Security group ID",
        "Account",
        "Region",
        "Direction",
        "Protocol",
        "Ports",
        "Source or destination",
        "Broadness",
        "Observed flows 30d",
        "Owner",
        "Risk score",
      ],
      ...filtered.map((item) => [
        item.group.name,
        item.group.id,
        item.group.accountName,
        item.group.region,
        item.rule.direction,
        item.rule.protocol,
        item.rule.ports,
        item.rule.source,
        item.category,
        String(item.rule.flows30d),
        item.group.owner,
        String(item.group.riskScore),
      ]),
    ];
    const csv = csvDocument(rows);
    downloadText(
      `gatewatch-broad-rules-${new Date().toISOString().slice(0, 10)}.csv`,
      csv,
      "text/csv;charset=utf-8",
    );
  }

  return (
    <section className="panel broad-rules-panel" id="broad-rules">
      <div className="broad-rules-header">
        <div>
          <div className="title-badges">
            <span className="severity-badge severity-critical">
              <span /> Primary view
            </span>
            <span className="version-chip">Rule-level inventory</span>
          </div>
          <h2>Potentially overbroad rules</h2>
          <p>
            Start with unrestricted internet access, then inspect broad CIDRs,
            all-traffic permissions, and wide port ranges.
          </p>
        </div>
        <button
          className="button button-secondary"
          onClick={exportRules}
          disabled={!filtered.length}
        >
          <Download size={15} /> Export {filtered.length} rules
        </button>
      </div>
      <div className="broad-rule-filters">
        <label className="table-search">
          <Search size={15} />
          <input
            value={ruleQuery}
            onChange={(event) => setRuleQuery(event.target.value)}
            placeholder="Search group, account, owner, CIDR…"
            aria-label="Search broad security-group rules"
          />
        </label>
        <label className="filter-select">
          <ArrowDownToLine size={14} />
          <select
            value={direction}
            onChange={(event) =>
              setDirection(
                event.target.value as "all" | "Ingress" | "Egress",
              )
            }
            aria-label="Filter broad rules by direction"
          >
            <option value="all">Ingress and egress</option>
            <option value="Ingress">Ingress only</option>
            <option value="Egress">Egress only</option>
          </select>
        </label>
        <label className="filter-select">
          <Filter size={14} />
          <select
            value={category}
            onChange={(event) => setCategory(event.target.value)}
            aria-label="Filter by broadness category"
          >
            <option value="all">All broadness types</option>
            <option value="Internet-wide">0.0.0.0/0 or ::/0</option>
            <option value="All traffic">All traffic</option>
            <option value="Broad CIDR">Broad CIDR</option>
            <option value="Wide port range">Wide port range</option>
          </select>
        </label>
      </div>
      <div className="broad-rule-summary">
        <span>
          <strong>{filtered.length}</strong> potentially broad rules
        </span>
        <span>
          {
            filtered.filter(
              (item) => item.rule.source === "0.0.0.0/0",
            ).length
          }{" "}
          IPv4 internet-wide ·{" "}
          {filtered.filter((item) => item.rule.source === "::/0").length} IPv6
          internet-wide
        </span>
      </div>
      {filtered.length ? (
        <div className="table-wrap broad-rule-table">
          <table>
            <thead>
              <tr>
                <th>Security group</th>
                <th>Direction</th>
                <th>Protocol / ports</th>
                <th>Source / destination</th>
                <th>Why it may be broad</th>
                <th>Observed use</th>
                <th>Risk</th>
                <th>
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => (
                <tr key={`${item.group.id}-${item.rule.id}`}>
                  <td>
                    <button
                      className="group-link"
                      onClick={() => onSelect(item.group)}
                    >
                      <span
                        className={`resource-icon icon-${item.group.severity}`}
                      >
                        <Network size={16} />
                      </span>
                      <span>
                        <strong>{item.group.name}</strong>
                        <small>
                          {item.group.accountName} · {item.group.region}
                        </small>
                      </span>
                    </button>
                  </td>
                  <td>
                    <span
                      className={`direction-chip direction-${item.rule.direction.toLowerCase()}`}
                    >
                      {item.rule.direction === "Ingress" ? (
                        <ArrowDownToLine size={12} />
                      ) : (
                        <ArrowUpRight size={12} />
                      )}
                      {item.rule.direction}
                    </span>
                  </td>
                  <td>
                    <strong className="cell-primary">
                      {item.rule.protocol} · {item.rule.ports}
                    </strong>
                    <small>{item.rule.id}</small>
                  </td>
                  <td>
                    <code
                      className={
                        item.category === "Internet-wide"
                          ? "cidr-chip cidr-public"
                          : "cidr-chip"
                      }
                    >
                      {item.rule.source}
                    </code>
                    <small>{item.rule.sourceLabel}</small>
                  </td>
                  <td>
                    <span className="broadness-cell">
                      <strong>{item.category}</strong>
                      <small>{item.reason}</small>
                    </span>
                  </td>
                  <td>
                    <strong className="cell-primary">
                      {item.rule.flows30d.toLocaleString()} flows
                    </strong>
                    <small>Last seen {item.rule.lastObserved}</small>
                  </td>
                  <td>
                    <RiskScore score={item.group.riskScore} />
                  </td>
                  <td>
                    <button
                      className="button button-small"
                      onClick={() => onReview(item.group)}
                    >
                      Review
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
            <ShieldCheck size={24} />
          </div>
          <h3>No broad rules match</h3>
          <p>Adjust the direction, broadness type, or search query.</p>
          <button
            className="button button-secondary"
            onClick={() => {
              setDirection("all");
              setCategory("all");
              setRuleQuery("");
            }}
          >
            Clear filters
          </button>
        </div>
      )}
    </section>
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
  const internetWide = broadRules.filter(
    (item) =>
      item.rule.source === "0.0.0.0/0" || item.rule.source === "::/0",
  );
  const broadIngress = broadRules.filter(
    (item) => item.rule.direction === "Ingress",
  );
  const broadEgress = broadRules.filter(
    (item) => item.rule.direction === "Egress",
  );
  const affectedGroups = new Set(broadRules.map((item) => item.group.id));
  const scrollToBroadRules = () =>
    document
      .getElementById("broad-rules")
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  return (
    <>
      <PageHeader
        eyebrow="Security-group exposure"
        title="Find rules that may be too broad."
        description="Start with 0.0.0.0/0 and ::/0, then review broad CIDRs, unrestricted protocols, and wide port ranges with traffic and reachability context."
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
          icon={<ExternalLink size={18} />}
          label="Internet-wide rules"
          value={String(internetWide.length)}
          helper="0.0.0.0/0 or ::/0"
          trend={`${new Set(
            internetWide
              .filter((item) => item.group.severity === "critical")
              .map((item) => item.group.id),
          ).size} critical groups`}
          tone="critical"
          onClick={scrollToBroadRules}
        />
        <MetricCard
          icon={<ArrowDownToLine size={18} />}
          label="Broad ingress"
          value={String(broadIngress.length)}
          helper="Potentially excessive sources"
          trend={`${broadIngress.filter((item) => item.rule.flows30d === 0).length} unused`}
          tone="warning"
          onClick={scrollToBroadRules}
        />
        <MetricCard
          icon={<ArrowUpRight size={18} />}
          label="Broad egress"
          value={String(broadEgress.length)}
          helper="Potentially excessive destinations"
          trend={`${broadEgress.filter((item) => item.rule.protocol === "All").length} all-traffic`}
          tone="attention"
          onClick={scrollToBroadRules}
        />
        <MetricCard
          icon={<Network size={18} />}
          label="Groups affected"
          value={String(affectedGroups.size)}
          helper="At least one broad rule"
          trend={`${reviewQueue.length} due review`}
          tone="neutral"
          onClick={() => onNavigate("reviews")}
        />
      </section>

      <BroadRulesPanel onSelect={onSelect} onReview={onReview} />

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

export function InventoryView({
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

function AccessExplorerView({
  onSelect,
  onReview,
  onToast,
}: {
  onSelect: (group: SecurityGroup) => void;
  onReview: (group: SecurityGroup) => void;
  onToast: (message: string) => void;
}) {
  const [accessQuery, setAccessQuery] = useState(accessQueryExamples[0]);
  const [executedQuery, setExecutedQuery] = useState(accessQueryExamples[0]);
  const [running, setRunning] = useState(false);
  const [savedQueries, setSavedQueries] = useState<string[]>([
    "Internet → production compute",
    "Development → production",
  ]);

  const results = useMemo(() => {
    const normalized = executedQuery.toLowerCase();
    if (normalized.includes("development") && normalized.includes("production")) {
      return securityGroups.filter(
        (group) =>
          group.environment === "Production" &&
          (group.name.includes("shared") ||
            group.findings.some((finding) =>
              finding.toLowerCase().includes("broad"),
            )),
      );
    }
    if (
      normalized.includes("outbound") ||
      normalized.includes("egress")
    ) {
      return securityGroups.filter((group) =>
        group.rules.some(
          (rule) =>
            rule.direction === "Egress" &&
            rule.source === "0.0.0.0/0" &&
            (rule.protocol === "All" || rule.ports === "All"),
        ),
      );
    }
    if (normalized.includes("changed") || normalized.includes("week")) {
      return securityGroups.filter(
        (group) =>
          !group.change.approved &&
          group.paths.some(
            (path) =>
              path.status === "reachable" && path.source === "Internet",
          ),
      );
    }
    return securityGroups.filter(
      (group) =>
        group.environment === "Production" &&
        group.paths.some(
          (path) =>
            path.status === "reachable" && path.source === "Internet",
        ),
    );
  }, [executedQuery]);

  function runQuery(next = accessQuery) {
    if (!next.trim()) return;
    setAccessQuery(next);
    setRunning(true);
    window.setTimeout(() => {
      setExecutedQuery(next.trim());
      setRunning(false);
    }, 520);
  }

  function saveQuery() {
    const normalized = executedQuery.trim();
    if (!normalized || savedQueries.includes(normalized)) {
      onToast("This access question is already saved.");
      return;
    }
    setSavedQueries((current) => [...current, normalized]);
    onToast("Saved access question for repeat evaluation.");
  }

  return (
    <>
      <PageHeader
        eyebrow="Deterministic access query"
        title="Ask what can reach what."
        description="Translate an access question into explainable AWS path checks. Gatewatch returns configuration, reachability, traffic, attribution, authorization, and coverage separately."
      />
      <section className="access-query-hero">
        <div className="access-query-icon">
          <Search size={22} />
        </div>
        <label>
          <span>Access question</span>
          <div>
            <input
              value={accessQuery}
              onChange={(event) => setAccessQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") runQuery();
              }}
              aria-label="Ask an access question"
            />
            <button
              className="button button-primary"
              onClick={() => runQuery()}
              disabled={running || !accessQuery.trim()}
            >
              {running ? <RefreshCw size={16} className="spin" /> : <Route size={16} />}
              {running ? "Analyzing…" : "Analyze access"}
            </button>
          </div>
        </label>
        <div className="query-examples">
          {accessQueryExamples.map((example) => (
            <button key={example} onClick={() => runQuery(example)}>
              {example}
            </button>
          ))}
        </div>
      </section>

      <div className="query-layout">
        <aside className="panel saved-query-panel">
          <div className="panel-header">
            <div>
              <h2>Saved questions</h2>
              <p>Re-evaluated as AWS state changes</p>
            </div>
            <button
              className="icon-button"
              aria-label="Save current access question"
              onClick={saveQuery}
            >
              <Save size={15} />
            </button>
          </div>
          <div className="saved-query-list">
            {savedQueries.map((saved) => (
              <button
                key={saved}
                className={executedQuery === saved ? "active" : ""}
                onClick={() => runQuery(saved)}
              >
                <Search size={14} />
                <span>{saved}</span>
                <ChevronRight size={14} />
              </button>
            ))}
          </div>
          <div className="query-engine-note">
            <Braces size={17} />
            <div>
              <strong>Deterministic execution</strong>
              <p>
                Natural language only selects a structured query. It cannot
                approve or change AWS access.
              </p>
            </div>
          </div>
        </aside>

        <section className="panel query-results-panel" aria-live="polite">
          <div className="query-result-header">
            <div>
              <span className="result-count">{results.length}</span>
              <div>
                <h2>Access paths matched</h2>
                <p>{executedQuery}</p>
              </div>
            </div>
            <span className="confidence-badge">Static + observed evidence</span>
          </div>
          <div className="evidence-semantics" aria-label="Evidence semantics">
            {[
              ["Configured", "Config"],
              ["Reachable", "Analyzer"],
              ["Observed", "Flow Logs"],
              ["Attributed", "CloudTrail"],
              ["Authorized", "Intent"],
              ["Complete", "Coverage"],
            ].map(([label, source]) => (
              <span key={label}>
                <Check size={12} />
                <strong>{label}</strong>
                <small>{source}</small>
              </span>
            ))}
          </div>
          {results.length ? (
            <div className="access-result-list">
              {results.map((group) => {
                const matchedPath =
                  group.paths.find((path) => path.status === "reachable") ??
                  group.paths[0];
                return (
                  <article key={group.id}>
                    <div className="access-result-main">
                      <span className={`resource-icon icon-${group.severity}`}>
                        <Route size={17} />
                      </span>
                      <div>
                        <div className="title-badges">
                          <SeverityBadge severity={group.severity} />
                          <span
                            className={`intent-chip intent-${group.intent.status}`}
                          >
                            {group.intent.status.replaceAll("-", " ")}
                          </span>
                        </div>
                        <button onClick={() => onSelect(group)}>
                          {matchedPath.source} → {matchedPath.destination}
                        </button>
                        <p>
                          {matchedPath.service} · {group.name} ·{" "}
                          {group.accountName}
                        </p>
                      </div>
                      <RiskScore score={group.riskScore} />
                    </div>
                    <div className="access-result-proof">
                      <span>
                        <strong>Reachable</strong>
                        {matchedPath.confidence} confidence
                      </span>
                      <span>
                        <strong>Observed</strong>
                        {group.traffic.accepted30d.toLocaleString()} accepted
                      </span>
                      <span>
                        <strong>Authorization</strong>
                        {group.intent.status === "matched"
                          ? group.intent.ticket
                          : "Drift detected"}
                      </span>
                      <span>
                        <strong>Coverage</strong>
                        {group.traffic.coverage}% flow evidence
                      </span>
                    </div>
                    <div className="access-result-actions">
                      <button
                        className="text-button"
                        onClick={() => onSelect(group)}
                      >
                        Inspect full evidence <ChevronRight size={14} />
                      </button>
                      <button
                        className="button button-small"
                        onClick={() => onReview(group)}
                      >
                        Review access
                      </button>
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <div className="empty-state">
              <div>
                <ShieldCheck size={24} />
              </div>
              <h3>No matching path found</h3>
              <p>
                Gatewatch found no supported configured path matching this
                question in the current evidence snapshot.
              </p>
            </div>
          )}
        </section>
      </div>
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

function ApplicationsView({
  onSelect,
  onNavigate,
}: {
  onSelect: (group: SecurityGroup) => void;
  onNavigate: (view: View) => void;
}) {
  const [applicationQuery, setApplicationQuery] = useState("");
  const [tier, setTier] = useState("all");
  const [selectedId, setSelectedId] = useState(applications[0].id);
  const visibleApplications = applications.filter((application) => {
    const searchable = [
      application.name,
      application.owner,
      application.technicalOwner,
      application.tags.join(" "),
    ]
      .join(" ")
      .toLowerCase();
    return (
      (!applicationQuery ||
        searchable.includes(applicationQuery.toLowerCase())) &&
      (tier === "all" || application.tier === tier)
    );
  });
  const selected =
    applications.find((application) => application.id === selectedId) ??
    visibleApplications[0] ??
    applications[0];
  const linkedGroups = securityGroups.filter((group) =>
    selected.securityGroupIds.includes(group.id),
  );

  return (
    <>
      <PageHeader
        eyebrow="Business context"
        title="Protect applications, not rule IDs."
        description="Map cloud tags and resource relationships into owned applications, crown jewels, approved dependencies, and business impact."
        actions={
          <button
            className="button button-primary"
            onClick={() => onNavigate("campaigns")}
          >
            <CalendarCheck2 size={16} /> Recertify application
          </button>
        }
      />
      <section className="application-summary">
        <div>
          <span className="application-summary-icon crown">
            <Crown size={18} />
          </span>
          <p>
            <strong>
              {applications.filter((app) => app.tier === "Crown jewel").length}
            </strong>
            <span>Crown-jewel applications</span>
          </p>
        </div>
        <div>
          <span className="application-summary-icon">
            <Route size={18} />
          </span>
          <p>
            <strong>
              {applications.reduce((sum, app) => sum + app.reachablePaths, 0)}
            </strong>
            <span>Reachable application paths</span>
          </p>
        </div>
        <div>
          <span className="application-summary-icon">
            <Users size={18} />
          </span>
          <p>
            <strong>100%</strong>
            <span>Named business owners</span>
          </p>
        </div>
        <div>
          <span className="application-summary-icon">
            <ShieldCheck size={18} />
          </span>
          <p>
            <strong>68%</strong>
            <span>Average protection score</span>
          </p>
        </div>
      </section>
      <div className="application-layout">
        <section className="panel application-index">
          <div className="application-filters">
            <label className="table-search">
              <Search size={15} />
              <input
                value={applicationQuery}
                onChange={(event) => setApplicationQuery(event.target.value)}
                placeholder="Search applications or owners"
                aria-label="Search applications"
              />
            </label>
            <label className="filter-select">
              <Filter size={14} />
              <select
                value={tier}
                onChange={(event) => setTier(event.target.value)}
                aria-label="Filter applications by tier"
              >
                <option value="all">All tiers</option>
                <option value="Crown jewel">Crown jewel</option>
                <option value="Business critical">Business critical</option>
                <option value="Important">Important</option>
                <option value="Standard">Standard</option>
              </select>
            </label>
          </div>
          <div className="application-list">
            {visibleApplications.map((application) => (
              <button
                key={application.id}
                className={selected.id === application.id ? "active" : ""}
                onClick={() => setSelectedId(application.id)}
              >
                <span
                  className={`app-tier-marker tier-${application.tier
                    .toLowerCase()
                    .replaceAll(" ", "-")}`}
                >
                  {application.tier === "Crown jewel" ? (
                    <Crown size={16} />
                  ) : (
                    <Box size={16} />
                  )}
                </span>
                <span>
                  <strong>{application.name}</strong>
                  <small>
                    {application.environment} · {application.owner}
                  </small>
                </span>
                <RiskScore score={application.riskScore} />
              </button>
            ))}
            {!visibleApplications.length ? (
              <div className="inline-empty">
                No application matches these filters.
              </div>
            ) : null}
          </div>
        </section>

        <section className="panel application-detail">
          <div className="application-detail-header">
            <div>
              <div className="title-badges">
                <span className="tier-chip">
                  {selected.tier === "Crown jewel" ? (
                    <Crown size={12} />
                  ) : null}
                  {selected.tier}
                </span>
                <span className="classification-chip">
                  {selected.dataClassification}
                </span>
                {selected.compliance.map((framework) => (
                  <span className="version-chip" key={framework}>
                    {framework}
                  </span>
                ))}
              </div>
              <h2>{selected.name}</h2>
              <p>{selected.description}</p>
            </div>
            <div className="protection-score">
              <span>Protection</span>
              <strong>{selected.protection}%</strong>
              <div>
                <i style={{ width: `${selected.protection}%` }} />
              </div>
            </div>
          </div>
          <div className="application-metadata">
            <div>
              <span>Business owner</span>
              <strong>{selected.owner}</strong>
            </div>
            <div>
              <span>Technical owner</span>
              <strong>{selected.technicalOwner}</strong>
            </div>
            <div>
              <span>Repository</span>
              <strong>{selected.repository.replace("github.com/acme/", "")}</strong>
            </div>
            <div>
              <span>Reachable paths</span>
              <strong>{selected.reachablePaths}</strong>
            </div>
          </div>
          <div className="application-detail-grid">
            <section>
              <div className="section-heading compact">
                <div>
                  <h3>Access dependencies</h3>
                  <p>Observed communication compared with approved intent</p>
                </div>
              </div>
              <div className="dependency-list">
                {selected.dependencies.map((dependency) => (
                  <div key={`${dependency.name}-${dependency.service}`}>
                    <span
                      className={
                        dependency.authorized
                          ? "dependency-approved"
                          : "dependency-drift"
                      }
                    >
                      {dependency.authorized ? (
                        <Check size={14} />
                      ) : (
                        <AlertTriangle size={14} />
                      )}
                    </span>
                    <p>
                      <strong>{dependency.name}</strong>
                      <small>{dependency.service}</small>
                    </p>
                    <em>
                      {dependency.authorized ? "Authorized" : "Outside intent"}
                    </em>
                  </div>
                ))}
              </div>
            </section>
            <section>
              <div className="section-heading compact">
                <div>
                  <h3>Security groups</h3>
                  <p>Configuration controls mapped to this application</p>
                </div>
              </div>
              <div className="application-group-list">
                {linkedGroups.map((group) => (
                  <button key={group.id} onClick={() => onSelect(group)}>
                    <span className={`resource-icon icon-${group.severity}`}>
                      <Network size={15} />
                    </span>
                    <span>
                      <strong>{group.name}</strong>
                      <small>{group.id}</small>
                    </span>
                    <RiskScore score={group.riskScore} />
                    <ChevronRight size={14} />
                  </button>
                ))}
              </div>
            </section>
          </div>
          <div className="tag-strip">
            <span>AWS identity mapping</span>
            {selected.tags.map((tag) => (
              <code key={tag}>{tag}</code>
            ))}
          </div>
        </section>
      </div>
    </>
  );
}

function PoliciesView({ onToast }: { onToast: (message: string) => void }) {
  const [scopeRecords, setScopeRecords] = useState<AccessScope[]>(accessScopes);
  const [selectedId, setSelectedId] = useState(accessScopes[0].id);
  const [creating, setCreating] = useState(false);
  const [previewing, setPreviewing] = useState(false);
  const [draftName, setDraftName] = useState("");
  const [draftDestination, setDraftDestination] = useState("Environment=Production");
  const [draftService, setDraftService] = useState("TCP 443");
  const [draftOwner, setDraftOwner] = useState("Cloud Security");
  const [draftError, setDraftError] = useState("");
  const [savingPolicy, setSavingPolicy] = useState(false);
  const selected =
    scopeRecords.find((scope) => scope.id === selectedId) ?? scopeRecords[0];

  useEffect(() => {
    let active = true;
    fetch("/api/governance")
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then(
        (payload: {
          policies?: {
            id: string;
            name: string;
            description: string;
            owner: string;
            destination: string;
            service: string;
            yaml: string;
          }[];
        }) => {
          if (!active || !payload.policies?.length) return;
          const customPolicies: AccessScope[] = payload.policies.map((policy) => ({
            id: policy.id,
            name: policy.name,
            description: policy.description,
            owner: policy.owner,
            destination: policy.destination,
            services: [policy.service],
            yaml: policy.yaml,
            version: 1,
            status: "draft",
            allowedSources: ["Owner approval required"],
            deniedConditions: ["Any source outside approved intent"],
            findings: 0,
            lastEvaluated: "Not yet evaluated",
          }));
          setScopeRecords((current) => [
            ...current,
            ...customPolicies.filter(
              (policy) => !current.some((item) => item.id === policy.id),
            ),
          ]);
        },
      )
      .catch(() => {
        // The built-in policy library remains usable if durable storage is unavailable.
      });
    return () => {
      active = false;
    };
  }, []);

  async function createPolicy() {
    if (draftName.trim().length < 5) {
      setDraftError("Give the access policy a descriptive name.");
      return;
    }
    if (!draftOwner.trim()) {
      setDraftError("Every policy requires an accountable owner.");
      return;
    }
    const id = `scope-${Date.now()}`;
    const record: AccessScope = {
      id,
      name: draftName.trim(),
      description: `Controls approved access to ${draftDestination}.`,
      owner: draftOwner.trim(),
      version: 1,
      status: "draft",
      destination: draftDestination.trim(),
      allowedSources: ["Owner approval required"],
      deniedConditions: ["Any source outside approved intent"],
      services: [draftService.trim()],
      findings: 0,
      lastEvaluated: "Not yet evaluated",
      yaml: `name: ${draftName
        .trim()
        .toLowerCase()
        .replaceAll(/[^a-z0-9]+/g, "-")}
destination:
  selector: ${draftDestination.trim()}
services:
  - ${draftService.trim().toLowerCase().replace(" ", "/")}
allowed_sources:
  - approval: application-owner
owner: ${draftOwner.trim().toLowerCase().replaceAll(" ", "-")}
mode: preview`,
    };
    setSavingPolicy(true);
    setDraftError("");
    try {
      const response = await fetch("/api/governance", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          kind: "policy",
          record: {
            id: record.id,
            name: record.name,
            description: record.description,
            owner: record.owner,
            destination: record.destination,
            service: record.services[0],
            yaml: record.yaml,
          },
        }),
      });
      const payload = (await response.json()) as { error?: string };
      if (!response.ok) {
        throw new Error(payload.error ?? "The policy could not be saved.");
      }
      setScopeRecords((current) => [...current, record]);
      setSelectedId(id);
      setCreating(false);
      setDraftName("");
      onToast("Draft access policy saved. Run a preview before activation.");
    } catch (error) {
      setDraftError(
        error instanceof Error ? error.message : "The policy could not be saved.",
      );
    } finally {
      setSavingPolicy(false);
    }
  }

  async function policyAction(action: "preview" | "activate") {
    setPreviewing(true);
    try {
      const response = await fetch("/api/governance", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          kind: "policy-action",
          record: { policyId: selected.id, action },
        }),
      });
      const payload = (await response.json()) as {
        record?: {
          status: string;
          evaluation?: { violations?: number };
        };
        error?: string;
      };
      if (!response.ok || !payload.record) {
        throw new Error(payload.error ?? "The policy action could not be completed.");
      }
      setScopeRecords((current) =>
        current.map((scope) =>
          scope.id === selected.id
            ? {
                ...scope,
                status: action === "activate" ? "active" : scope.status,
                lastEvaluated: "Just now",
                findings: payload.record?.evaluation?.violations ?? scope.findings,
              }
            : scope,
        ),
      );
      onToast(
        action === "activate"
          ? `${selected.name} activated after its evidence preview.`
          : `${selected.name} preview completed against the current AWS evidence snapshot.`,
      );
    } catch (caught) {
      setDraftError(
        caught instanceof Error
          ? caught.message
          : "The policy action could not be completed.",
      );
    } finally {
      setPreviewing(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Intent as code"
        title="Versioned access policies"
        description="Define acceptable communication using accounts, tags, applications, services, and path conditions—then preview violations before activation."
        actions={
          <button
            className="button button-primary"
            onClick={() => setCreating(true)}
          >
            <BookOpenCheck size={16} /> New access policy
          </button>
        }
      />
      <div className="policy-layout">
        <section className="panel policy-index">
          <div className="panel-header">
            <div>
              <h2>Policy library</h2>
              <p>{scopeRecords.length} versioned access contracts</p>
            </div>
          </div>
          <div className="scope-list">
            {scopeRecords.map((scope) => (
              <button
                key={scope.id}
                className={scope.id === selected.id ? "active" : ""}
                onClick={() => setSelectedId(scope.id)}
              >
                <span className={`scope-status scope-${scope.status}`}>
                  {scope.status === "attention" ? (
                    <AlertTriangle size={14} />
                  ) : scope.status === "active" ? (
                    <Check size={14} />
                  ) : (
                    <Braces size={14} />
                  )}
                </span>
                <span>
                  <strong>{scope.name}</strong>
                  <small>
                    v{scope.version} · {scope.owner}
                  </small>
                </span>
                {scope.findings ? <em>{scope.findings}</em> : null}
              </button>
            ))}
          </div>
        </section>

        <section className="panel policy-workspace">
          <div className="policy-workspace-header">
            <div>
              <div className="title-badges">
                <span className={`scope-state scope-state-${selected.status}`}>
                  {selected.status}
                </span>
                <span className="version-chip">v{selected.version}</span>
              </div>
              <h2>{selected.name}</h2>
              <p>{selected.description}</p>
            </div>
            <div className="page-actions">
              <button
                className="button button-secondary"
                onClick={() =>
                  downloadText(
                    `${selected.id}.yaml`,
                    selected.yaml,
                    "text/yaml",
                  )
                }
              >
                <Download size={15} /> Export YAML
              </button>
              <button
                className="button button-primary"
                onClick={() => void policyAction("preview")}
                disabled={previewing}
              >
                <RefreshCw
                  size={15}
                  className={previewing ? "spin" : ""}
                />
                {previewing ? "Evaluating…" : "Preview against AWS"}
              </button>
              {selected.status !== "active" ? (
                <button
                  className="button button-dark"
                  onClick={() => void policyAction("activate")}
                  disabled={previewing || selected.lastEvaluated === "Not yet evaluated"}
                  title={selected.lastEvaluated === "Not yet evaluated" ? "Run an AWS preview before activation" : undefined}
                >
                  <ShieldCheck size={15} /> Activate version
                </button>
              ) : null}
            </div>
          </div>
          {draftError ? <div className="form-error" role="alert"><CircleAlert size={15} />{draftError}</div> : null}
          <div className="policy-facts">
            <div>
              <span>Destination</span>
              <strong>{selected.destination}</strong>
            </div>
            <div>
              <span>Services</span>
              <strong>{selected.services.join(", ")}</strong>
            </div>
            <div>
              <span>Owner</span>
              <strong>{selected.owner}</strong>
            </div>
            <div>
              <span>Latest result</span>
              <strong>
                {selected.findings} findings · {selected.lastEvaluated}
              </strong>
            </div>
          </div>
          <div className="policy-editor-grid">
            <section className="policy-code">
              <div>
                <span>gatewatch-access.yaml</span>
                <em>Policy as code</em>
              </div>
              <pre>
                <code>{selected.yaml}</code>
              </pre>
            </section>
            <section className="policy-meaning">
              <h3>Human-readable meaning</h3>
              <div>
                <span className="meaning-icon meaning-allow">
                  <Check size={14} />
                </span>
                <p>
                  <strong>Allowed sources</strong>
                  {selected.allowedSources.join(", ")}
                </p>
              </div>
              <div>
                <span className="meaning-icon meaning-deny">
                  <X size={14} />
                </span>
                <p>
                  <strong>Denied conditions</strong>
                  {selected.deniedConditions.join(", ")}
                </p>
              </div>
              <div>
                <span className="meaning-icon">
                  <Eye size={14} />
                </span>
                <p>
                  <strong>Evaluation behavior</strong>
                  Static reachability is kept separate from observed traffic
                  and authorization evidence.
                </p>
              </div>
            </section>
          </div>
        </section>
      </div>

      {creating ? (
        <div
          className="modal-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setCreating(false);
          }}
        >
          <section
            className="review-modal policy-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="new-policy-title"
          >
            <div className="modal-header">
              <div>
                <span className="eyebrow">Policy as code</span>
                <h2 id="new-policy-title">Create access policy</h2>
                <p>Start in preview mode. Activation always requires review.</p>
              </div>
              <button
                className="icon-button"
                aria-label="Close policy form"
                onClick={() => setCreating(false)}
              >
                <X size={17} />
              </button>
            </div>
            <div className="policy-form-grid">
              <label>
                <span>Policy name</span>
                <input
                  value={draftName}
                  onChange={(event) => setDraftName(event.target.value)}
                  placeholder="e.g. Finance database boundary"
                  autoFocus
                />
              </label>
              <label>
                <span>Destination selector</span>
                <input
                  value={draftDestination}
                  onChange={(event) => setDraftDestination(event.target.value)}
                />
              </label>
              <label>
                <span>Service</span>
                <input
                  value={draftService}
                  onChange={(event) => setDraftService(event.target.value)}
                />
              </label>
              <label>
                <span>Accountable owner</span>
                <input
                  value={draftOwner}
                  onChange={(event) => setDraftOwner(event.target.value)}
                />
              </label>
            </div>
            {draftError ? (
              <div className="form-error" role="alert">
                <CircleAlert size={15} /> {draftError}
              </div>
            ) : null}
            <div className="modal-actions">
              <button
                className="button button-secondary"
                onClick={() => setCreating(false)}
              >
                Cancel
              </button>
              <button
                className="button button-primary"
                onClick={createPolicy}
                disabled={savingPolicy}
              >
                {savingPolicy ? "Saving…" : "Create preview policy"}
              </button>
            </div>
          </section>
        </div>
      ) : null}
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

function CampaignsView({
  onToast,
  onNavigate,
}: {
  onToast: (message: string) => void;
  onNavigate: (view: View) => void;
}) {
  type CampaignItemRecord = {
    id: string;
    campaignId: string;
    fingerprint: string;
    owner: string;
    status: string;
    decision: string;
    note: string;
  };
  const [campaignRecords, setCampaignRecords] = useState<Campaign[]>(campaigns);
  const [campaignItems, setCampaignItems] = useState<CampaignItemRecord[]>([]);
  const [decisionNote, setDecisionNote] = useState("");
  const [decisionBusy, setDecisionBusy] = useState("");
  const [selectedId, setSelectedId] = useState(campaigns[0].id);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [scope, setScope] = useState("Environment=Production");
  const [dueDate, setDueDate] = useState("2026-09-30");
  const [error, setError] = useState("");
  const [savingCampaign, setSavingCampaign] = useState(false);
  const selected =
    campaignRecords.find((campaign) => campaign.id === selectedId) ??
    campaignRecords[0];
  const progress = Math.round((selected.completed / selected.total) * 100);

  useEffect(() => {
    let active = true;
    fetch("/api/governance")
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then(
        (payload: {
          campaigns?: {
            id: string;
            name: string;
            description: string;
            owner: string;
            scope: string;
            dueDate: string;
            total: number;
            completed?: number;
            escalations?: number;
          }[];
          campaignItems?: CampaignItemRecord[];
        }) => {
          if (!active || !payload.campaigns?.length) return;
          const customCampaigns: Campaign[] = payload.campaigns.map(
            (campaign) => ({
              ...campaign,
              status: "scheduled",
              completed: Number(campaign.completed ?? 0),
              escalations: Number(campaign.escalations ?? 0),
              evidenceCoverage: campaign.total ? 100 : 0,
              reviewers: [
                {
                  name: "Application owners",
                  team: "Derived from AWS tags",
                  assigned: campaign.total,
                  complete: Number(campaign.completed ?? 0),
                },
              ],
            }),
          );
          setCampaignRecords((current) => [
            ...current,
            ...customCampaigns.filter(
              (campaign) => !current.some((item) => item.id === campaign.id),
            ),
          ]);
          setCampaignItems(payload.campaignItems ?? []);
        },
      )
      .catch(() => {
        // Built-in campaigns remain available if durable storage is recovering.
      });
    return () => {
      active = false;
    };
  }, []);

  async function createCampaign() {
    if (name.trim().length < 6) {
      setError("Give the campaign a descriptive name.");
      return;
    }
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dueDate)) {
      setError("Choose a valid due date.");
      return;
    }
    const id = `camp-${Date.now()}`;
    const campaign: Campaign = {
      id,
      name: name.trim(),
      description: `Owner attestation for ${scope}.`,
      owner: "Cloud Security",
      dueDate,
      status: "scheduled",
      scope,
      total: 12,
      completed: 0,
      escalations: 0,
      evidenceCoverage: 96,
      reviewers: [
        {
          name: "Application owners",
          team: "Derived from AWS tags",
          assigned: 12,
          complete: 0,
        },
      ],
    };
    setSavingCampaign(true);
    setError("");
    try {
      const response = await fetch("/api/governance", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          kind: "campaign",
          record: {
            id: campaign.id,
            name: campaign.name,
            description: campaign.description,
            owner: campaign.owner,
            scope: campaign.scope,
            dueDate: campaign.dueDate,
            total: campaign.total,
          },
        }),
      });
      const payload = (await response.json()) as {
        record?: { total?: number };
        error?: string;
      };
      if (!response.ok) {
        throw new Error(payload.error ?? "The campaign could not be saved.");
      }
      const savedCampaign = {
        ...campaign,
        total: payload.record?.total ?? campaign.total,
        reviewers: campaign.reviewers.map((reviewer) => ({
          ...reviewer,
          assigned: payload.record?.total ?? campaign.total,
        })),
      };
      setCampaignRecords((current) => [...current, savedCampaign]);
      const refreshed = await fetch("/api/governance", { cache: "no-store" });
      if (refreshed.ok) {
        const refreshedPayload = (await refreshed.json()) as { campaignItems?: CampaignItemRecord[] };
        setCampaignItems(refreshedPayload.campaignItems ?? []);
      }
      setSelectedId(id);
      setCreating(false);
      setName("");
      onToast("Recertification campaign scheduled with evidence snapshots.");
    } catch (campaignError) {
      setError(
        campaignError instanceof Error
          ? campaignError.message
          : "The campaign could not be saved.",
      );
    } finally {
      setSavingCampaign(false);
    }
  }

  function exportCampaign() {
    const packageContents = {
      campaign: selected,
      generatedAt: new Date().toISOString(),
      evidence: {
        immutableSnapshot: false,
        sources: ["Current Gatewatch evidence snapshots"],
        coverage: selected.evidenceCoverage,
      },
      items: campaignItems.filter((item) => item.campaignId === selected.id),
      note: "Campaign decisions and their captured evidence. Source snapshot identity is retained for verification.",
    };
    downloadText(
      `${selected.id}-evidence.json`,
      JSON.stringify(packageContents, null, 2),
      "application/json",
    );
    onToast("Campaign evidence package exported.");
  }

  async function decideCampaignItem(
    item: CampaignItemRecord,
    decision: "attest" | "remove" | "escalate",
  ) {
    if (decisionNote.trim().length < 8) {
      onToast("Add a short decision rationale before recording the attestation.");
      return;
    }
    setDecisionBusy(item.id);
    try {
      const response = await fetch("/api/governance", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          kind: "campaign-decision",
          record: { itemId: item.id, decision, note: decisionNote },
        }),
      });
      const payload = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "The campaign decision could not be saved.");
      setCampaignItems((current) =>
        current.map((candidate) =>
          candidate.id === item.id
            ? { ...candidate, status: decision === "escalate" ? "overdue" : "complete", decision, note: decisionNote }
            : candidate,
        ),
      );
      setCampaignRecords((current) => current.map((campaign) =>
        campaign.id === item.campaignId
          ? {
              ...campaign,
              completed: decision === "escalate" ? campaign.completed : campaign.completed + 1,
              escalations: decision === "escalate" ? campaign.escalations + 1 : campaign.escalations,
            }
          : campaign,
      ));
      setDecisionNote("");
      onToast(`Campaign decision recorded as ${decision}.`);
    } catch (caught) {
      onToast(caught instanceof Error ? caught.message : "The campaign decision could not be saved.");
    } finally {
      setDecisionBusy("");
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Access recertification"
        title="Govern access as a campaign."
        description="Assign application owners, track attestations, escalate overdue decisions, and produce a time-bound evidence package."
        actions={
          <button
            className="button button-primary"
            onClick={() => setCreating(true)}
          >
            <CalendarCheck2 size={16} /> New campaign
          </button>
        }
      />
      <div className="campaign-layout">
        <aside className="panel campaign-index">
          <div className="panel-header">
            <div>
              <h2>Campaigns</h2>
              <p>Active and scheduled owner attestations</p>
            </div>
          </div>
          <div className="campaign-list">
            {campaignRecords.map((campaign) => {
              const campaignProgress = Math.round(
                (campaign.completed / campaign.total) * 100,
              );
              return (
                <button
                  key={campaign.id}
                  className={selected.id === campaign.id ? "active" : ""}
                  onClick={() => setSelectedId(campaign.id)}
                >
                  <span className={`campaign-status campaign-${campaign.status}`}>
                    {campaign.status === "complete" ? (
                      <Check size={15} />
                    ) : (
                      <CalendarCheck2 size={15} />
                    )}
                  </span>
                  <span>
                    <strong>{campaign.name}</strong>
                    <small>
                      Due {campaign.dueDate} · {campaignProgress}% complete
                    </small>
                    <i>
                      <em style={{ width: `${campaignProgress}%` }} />
                    </i>
                  </span>
                </button>
              );
            })}
          </div>
        </aside>

        <section className="panel campaign-workspace">
          <div className="campaign-header">
            <div>
              <div className="title-badges">
                <span className={`scope-state scope-state-${selected.status}`}>
                  {selected.status}
                </span>
                <span className="version-chip">{selected.scope}</span>
              </div>
              <h2>{selected.name}</h2>
              <p>{selected.description}</p>
            </div>
            <div className="page-actions">
              <button
                className="button button-secondary"
                onClick={exportCampaign}
              >
                <Download size={15} /> Evidence package
              </button>
              <button
                className="button button-primary"
                onClick={() => {
                  onToast("Opened the campaign review queue.");
                  onNavigate("reviews");
                }}
              >
                Open decisions <ChevronRight size={15} />
              </button>
            </div>
          </div>
          <section className="campaign-progress-card">
            <div className="campaign-progress-ring">
              <strong>{progress}%</strong>
              <span>complete</span>
            </div>
            <div>
              <h3>
                {selected.completed} of {selected.total} access decisions
              </h3>
              <p>
                Evidence coverage is {selected.evidenceCoverage}%. Decisions
                preserve the evaluated configuration, paths, traffic, intent,
                and reviewer identity.
              </p>
              <div className="campaign-progress-bar">
                <span style={{ width: `${progress}%` }} />
              </div>
            </div>
            <dl>
              <div>
                <dt>Due date</dt>
                <dd>{selected.dueDate}</dd>
              </div>
              <div>
                <dt>Escalations</dt>
                <dd>{selected.escalations}</dd>
              </div>
              <div>
                <dt>Campaign owner</dt>
                <dd>{selected.owner}</dd>
              </div>
            </dl>
          </section>
          {campaignItems.some((item) => item.campaignId === selected.id) ? (
            <section className="campaign-decision-workspace">
              <div className="section-heading">
                <div>
                  <h3>Scoped access decisions</h3>
                  <p>Each item preserves the finding evidence captured when the campaign was created.</p>
                </div>
              </div>
              <label className="form-field">
                <span>Decision rationale</span>
                <textarea
                  value={decisionNote}
                  onChange={(event) => setDecisionNote(event.target.value)}
                  placeholder="Confirm why access remains appropriate or why it should be removed."
                  maxLength={1200}
                />
              </label>
              <div className="campaign-item-list">
                {campaignItems
                  .filter((item) => item.campaignId === selected.id)
                  .slice(0, 25)
                  .map((item) => (
                    <article key={item.id}>
                      <div>
                        <strong>{item.owner}</strong>
                        <small>{item.fingerprint}</small>
                      </div>
                      <span className={`finding-status status-${item.status}`}>{item.decision || item.status}</span>
                      <div className="page-actions">
                        <button className="button button-secondary" disabled={item.status === "complete" || decisionBusy === item.id} onClick={() => void decideCampaignItem(item, "attest")}>Attest</button>
                        <button className="button button-secondary" disabled={item.status === "complete" || decisionBusy === item.id} onClick={() => void decideCampaignItem(item, "remove")}>Remove</button>
                        <button className="button button-danger" disabled={item.status === "complete" || decisionBusy === item.id} onClick={() => void decideCampaignItem(item, "escalate")}>Escalate</button>
                      </div>
                    </article>
                  ))}
              </div>
            </section>
          ) : null}
          <div className="section-heading">
            <div>
              <h3>Reviewer progress</h3>
              <p>Assignments derived from application ownership</p>
            </div>
          </div>
          <div className="reviewer-table">
            <div className="reviewer-row reviewer-head">
              <span>Reviewer</span>
              <span>Team</span>
              <span>Progress</span>
              <span>Status</span>
            </div>
            {selected.reviewers.map((reviewer) => {
              const reviewerProgress = Math.round(
                (reviewer.complete / reviewer.assigned) * 100,
              );
              return (
                <div className="reviewer-row" key={reviewer.name}>
                  <span>
                    <i className="avatar">
                      {reviewer.name
                        .split(" ")
                        .map((word) => word[0])
                        .join("")
                        .slice(0, 2)}
                    </i>
                    <strong>{reviewer.name}</strong>
                  </span>
                  <span>{reviewer.team}</span>
                  <span>
                    <strong>
                      {reviewer.complete}/{reviewer.assigned}
                    </strong>
                    <i className="reviewer-progress">
                      <em style={{ width: `${reviewerProgress}%` }} />
                    </i>
                  </span>
                  <span>
                    <span
                      className={
                        reviewerProgress === 100
                          ? "review-complete"
                          : "review-pending"
                      }
                    >
                      {reviewerProgress === 100 ? "Complete" : "In progress"}
                    </span>
                  </span>
                </div>
              );
            })}
          </div>
        </section>
      </div>

      {creating ? (
        <div
          className="modal-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setCreating(false);
          }}
        >
          <section
            className="review-modal policy-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="campaign-title"
          >
            <div className="modal-header">
              <div>
                <span className="eyebrow">Governance workflow</span>
                <h2 id="campaign-title">Schedule recertification</h2>
                <p>Owners and evidence are resolved from the selected scope.</p>
              </div>
              <button
                className="icon-button"
                aria-label="Close campaign form"
                onClick={() => setCreating(false)}
              >
                <X size={17} />
              </button>
            </div>
            <div className="policy-form-grid">
              <label>
                <span>Campaign name</span>
                <input
                  value={name}
                  onChange={(event) => setName(event.target.value)}
                  placeholder="e.g. Q4 restricted data access"
                  autoFocus
                />
              </label>
              <label>
                <span>Scope</span>
                <select value={scope} onChange={(event) => setScope(event.target.value)}>
                  <option>Environment=Production</option>
                  <option>Environment=Shared</option>
                  <option>Environment=Development</option>
                </select>
              </label>
              <label>
                <span>Due date</span>
                <input
                  type="date"
                  value={dueDate}
                  onChange={(event) => setDueDate(event.target.value)}
                />
              </label>
            </div>
            {error ? (
              <div className="form-error" role="alert">
                <CircleAlert size={15} /> {error}
              </div>
            ) : null}
            <div className="modal-actions">
              <button
                className="button button-secondary"
                onClick={() => setCreating(false)}
              >
                Cancel
              </button>
              <button
                className="button button-primary"
                onClick={createCampaign}
                disabled={savingCampaign}
              >
                {savingCampaign ? "Scheduling…" : "Schedule campaign"}
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}

function RemediationView({
  onSelect,
  onToast,
  onNavigate,
}: {
  onSelect: (group: SecurityGroup) => void;
  onToast: (message: string) => void;
  onNavigate: (view: View) => void;
}) {
  const [selectedId, setSelectedId] = useState(remediations[0].id);
  const [confirming, setConfirming] = useState(false);
  const [requestState, setRequestState] = useState<{
    id: string;
    status: string;
  } | null>(null);
  const [requestBusy, setRequestBusy] = useState(false);
  const selected =
    remediations.find((remediation) => remediation.id === selectedId) ??
    remediations[0];
  const group =
    securityGroups.find((candidate) => candidate.id === selected.securityGroupId) ??
    securityGroups[0];
  const reduction = selected.currentRisk - selected.projectedRisk;

  async function createRequest() {
    setRequestBusy(true);
    const resourceKey = canonicalSecurityGroupKey(group);
    const fingerprint = canonicalFindingFingerprint(group, selected.id);
    const artifact = {
      type: selected.artifact,
      status: "draft",
      remediationId: selected.id,
      securityGroupId: selected.securityGroupId,
      proposedChange: selected.change,
      evidence: {
        pathsBroken: selected.pathsBroken,
        assetsProtected: selected.assetsProtected,
        legitimateFlowsPreserved: selected.legitimateFlowsPreserved,
        confidence: selected.confidence,
      },
      approvalsRequired: ["Cloud Security", "Application owner"],
      execution: "Disabled until explicit AWS deployment configuration",
    };
    try {
      const response = await fetch("/api/remediations", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          action: "create",
          id: selected.id,
          fingerprint,
          canonicalResourceKey: resourceKey,
          proposedChange: selected.change,
          evidenceBefore: {
            snapshotId: group.change.eventId,
            riskScore: selected.currentRisk,
            publicRules: group.publicRules,
            paths: group.paths,
            trafficCoverage: group.traffic.coverage,
          },
        }),
      });
      const payload = (await response.json()) as {
        record?: { id: string; status: string; deliveryId: string };
        error?: string;
      };
      if (!response.ok || !payload.record) {
        throw new Error(payload.error ?? "The remediation request could not be saved.");
      }
      setConfirming(false);
      setRequestState(payload.record);
      downloadText(
        `${selected.id}-change-request.json`,
        JSON.stringify({ ...artifact, gatewatchRecord: payload.record }, null, 2),
        "application/json",
      );
      onToast("Draft remediation saved and queued for an IaC handoff; no AWS access was modified.");
    } catch (caught) {
      onToast(caught instanceof Error ? caught.message : "The remediation request could not be saved.");
    } finally {
      setRequestBusy(false);
    }
  }

  async function remediationAction(action: "approve" | "verify") {
    if (!requestState) return;
    setRequestBusy(true);
    try {
      const response = await fetch("/api/remediations", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action, id: requestState.id }),
      });
      const payload = (await response.json()) as {
        record?: { status: string };
        verification?: { status: string };
        error?: string;
      };
      if (!response.ok) throw new Error(payload.error ?? "The remediation action failed.");
      const status = payload.record?.status ?? payload.verification?.status ?? requestState.status;
      setRequestState({ ...requestState, status });
      onToast(action === "approve" ? "Remediation approved for controlled IaC delivery." : `Post-change verification ${status}.`);
    } catch (caught) {
      onToast(caught instanceof Error ? caught.message : "The remediation action failed.");
    } finally {
      setRequestBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Remediation leverage"
        title="Fix the paths that matter most."
        description="Rank safe changes by dangerous paths eliminated, business-critical assets protected, legitimate traffic preserved, and implementation confidence."
        actions={
          <button
            className="button button-secondary"
            onClick={() => onNavigate("handoffs")}
          >
            <FileCode2 size={16} /> View AWS handoffs
          </button>
        }
      />
      <section className="leverage-banner">
        <span>
          <Target size={21} />
        </span>
        <div>
          <strong>Four changes can eliminate 36 high-risk paths</strong>
          <p>
            The ranking favors choke points that protect multiple assets while
            preserving observed, authorized communication.
          </p>
        </div>
        <div>
          <strong>15</strong>
          <span>assets protected</span>
        </div>
        <div>
          <strong>99.9%</strong>
          <span>flows preserved</span>
        </div>
      </section>
      <div className="remediation-layout">
        <section className="panel remediation-index">
          <div className="panel-header">
            <div>
              <h2>Ranked changes</h2>
              <p>Highest risk reduction per controlled change</p>
            </div>
          </div>
          <div className="remediation-list">
            {remediations.map((remediation, index) => (
              <button
                key={remediation.id}
                className={selected.id === remediation.id ? "active" : ""}
                onClick={() => setSelectedId(remediation.id)}
              >
                <span className="remediation-rank">
                  {String(index + 1).padStart(2, "0")}
                </span>
                <span>
                  <strong>{remediation.title}</strong>
                  <small>
                    {remediation.application} · {remediation.pathsBroken} paths
                  </small>
                </span>
                <span className="risk-reduction">
                  -{remediation.currentRisk - remediation.projectedRisk}
                </span>
              </button>
            ))}
          </div>
        </section>
        <section className="panel remediation-workspace">
          <div className="remediation-header">
            <div>
              <div className="title-badges">
                <SeverityBadge severity={selected.severity} />
                <span className="confidence-badge">
                  {selected.confidence} confidence
                </span>
                <span className="version-chip">{selected.effort} effort</span>
              </div>
              <h2>{selected.title}</h2>
              <p>{selected.rationale}</p>
            </div>
            <button
              className="button button-secondary"
              onClick={() => onSelect(group)}
            >
              View source evidence
            </button>
          </div>
          <div className="simulation-scoreboard">
            <div>
              <span>Current risk</span>
              <RiskScore score={selected.currentRisk} />
            </div>
            <ArrowRight size={21} />
            <div>
              <span>Projected risk</span>
              <RiskScore score={selected.projectedRisk} />
            </div>
            <div className="simulation-reduction">
              <strong>-{reduction}</strong>
              <span>risk reduction</span>
            </div>
          </div>
          <div className="remediation-impact-grid">
            <div>
              <Route size={18} />
              <strong>{selected.pathsBroken}</strong>
              <span>dangerous paths eliminated</span>
            </div>
            <div>
              <ShieldCheck size={18} />
              <strong>{selected.assetsProtected}</strong>
              <span>critical assets protected</span>
            </div>
            <div>
              <Radio size={18} />
              <strong>{selected.legitimateFlowsPreserved}%</strong>
              <span>observed flows preserved</span>
            </div>
          </div>
          <section className="proposed-change">
            <span className="proposed-change-icon">
              <Braces size={18} />
            </span>
            <div>
              <span>Proposed least-privilege change</span>
              <strong>{selected.change}</strong>
            </div>
          </section>
          <div className="safeguard-list">
            <h3>Safety checks before implementation</h3>
            {selected.safeguards.map((safeguard) => (
              <div key={safeguard}>
                <CircleCheck size={14} /> {safeguard}
              </div>
            ))}
          </div>
          <div className="remediation-footer">
            <span>
              <ShieldEllipsis size={16} />
              Simulation only · no AWS write permission
            </span>
            <button
              className="button button-primary"
              onClick={() => setConfirming(true)}
            >
              Create draft change request
            </button>
            {requestState ? (
              <>
                <span className={`finding-status status-${requestState.status}`}>{requestState.status}</span>
                {requestState.status === "draft" ? <button className="button button-secondary" disabled={requestBusy} onClick={() => void remediationAction("approve")}>Approve handoff</button> : null}
                {requestState.status !== "draft" ? <button className="button button-secondary" disabled={requestBusy} onClick={() => void remediationAction("verify")}>Verify current AWS state</button> : null}
              </>
            ) : null}
          </div>
        </section>
      </div>
      {confirming ? (
        <div className="modal-backdrop" role="presentation">
          <section
            className="review-modal confirm-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-change-title"
          >
            <div className="modal-header">
              <div>
                <span className="eyebrow">Controlled handoff</span>
                <h2 id="confirm-change-title">Generate a draft request?</h2>
                <p>
                  This downloads a review artifact. It does not connect to AWS,
                  alter infrastructure, or bypass application-owner approval.
                </p>
              </div>
            </div>
            <div className="confirmation-summary">
              <strong>{selected.title}</strong>
              <span>{selected.artifact}</span>
            </div>
            <div className="modal-actions">
              <button
                className="button button-secondary"
                onClick={() => setConfirming(false)}
              >
                Cancel
              </button>
              <button className="button button-primary" disabled={requestBusy} onClick={() => void createRequest()}>
                {requestBusy ? "Saving…" : "Generate draft"}
              </button>
            </div>
          </section>
        </div>
      ) : null}
    </>
  );
}

function CloudTrailImportView({
  imported,
  setImported,
  onSelect,
  onToast,
}: {
  imported: CloudTrailSessionImport | null;
  setImported: (value: CloudTrailSessionImport | null) => void;
  onSelect: (group: SecurityGroup) => void;
  onToast: (message: string) => void;
}) {
  const [dragging, setDragging] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [importError, setImportError] = useState("");
  const [eventQuery, setEventQuery] = useState("");
  const [effectFilter, setEffectFilter] = useState("all");
  const [eventPage, setEventPage] = useState(1);
  const eventsPerPage = 100;

  const visibleEvents = useMemo(() => {
    if (!imported) return [];
    return imported.result.events.filter((event) => {
      const linkedNames = event.groupIds
        .map(
          (id) =>
            securityGroups.find((group) => group.id === id)?.name ?? id,
        )
        .join(" ");
      const searchable = [
        event.eventName,
        event.actor,
        event.sourceIp,
        event.region,
        event.accountId,
        event.groupIds.join(" "),
        event.cidrs.join(" "),
        linkedNames,
      ]
        .join(" ")
        .toLowerCase();
      return (
        (effectFilter === "all" || event.effect === effectFilter) &&
        (!eventQuery || searchable.includes(eventQuery.toLowerCase()))
      );
    });
  }, [effectFilter, eventQuery, imported]);
  const totalEventPages = Math.max(
    1,
    Math.ceil(visibleEvents.length / eventsPerPage),
  );
  const pageEvents = visibleEvents.slice(
    (eventPage - 1) * eventsPerPage,
    eventPage * eventsPerPage,
  );

  async function processFile(file: File) {
    setProcessing(true);
    setImportError("");
    try {
      const text = await readCloudTrailFile(file);
      const result = parseCloudTrailText(text);
      setImported({
        fileName: file.name.slice(0, 240),
        fileSize: file.size,
        importedAt: new Date().toISOString(),
        result,
      });
      setEventQuery("");
      setEffectFilter("all");
      setEventPage(1);
      onToast(
        `Imported ${result.events.length.toLocaleString()} security-group events locally.`,
      );
    } catch (error) {
      setImportError(
        error instanceof Error
          ? error.message
          : "The CloudTrail log could not be imported.",
      );
    } finally {
      setProcessing(false);
    }
  }

  function handleDrop(event: React.DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    setDragging(false);
    if (event.dataTransfer.files.length !== 1) {
      setImportError("Drop one CloudTrail JSON or JSON.GZ file at a time.");
      return;
    }
    void processFile(event.dataTransfer.files[0]);
  }

  function exportNormalizedEvents() {
    if (!imported) return;
    const rows = [
      [
        "Event time",
        "Event",
        "Effect",
        "Direction",
        "Security groups",
        "CIDRs",
        "Protocol",
        "Ports",
        "Actor",
        "Source IP",
        "Account",
        "Region",
        "AWS result",
      ],
      ...visibleEvents.map((event) => [
        event.eventTime,
        event.eventName,
        event.effect,
        event.direction,
        event.groupIds.join("; "),
        event.cidrs.join("; "),
        event.protocol,
        event.ports,
        event.actor,
        event.sourceIp,
        event.accountId,
        event.region,
        event.errorCode || "Success",
      ]),
    ];
    const csv = csvDocument(rows);
    downloadText(
      `gatewatch-cloudtrail-events-${new Date()
        .toISOString()
        .slice(0, 10)}.csv`,
      csv,
      "text/csv;charset=utf-8",
    );
    onToast(`Exported ${visibleEvents.length.toLocaleString()} normalized events.`);
  }

  const correlatedEvents =
    imported?.result.events.filter((event) =>
      event.groupIds.some((id) =>
        securityGroups.some((group) => group.id === id),
      ),
    ).length ?? 0;
  const failedEvents =
    imported?.result.events.filter((event) => event.errorCode).length ?? 0;

  return (
    <>
      <PageHeader
        eyebrow="Local evidence import"
        title="Drag in an AWS CloudTrail log."
        description="Extract security-group changes, identify rules opened to the internet, and correlate events with Gatewatch groups without sending the file anywhere."
        actions={
          imported ? (
            <>
              <button
                className="button button-secondary"
                onClick={exportNormalizedEvents}
                disabled={!visibleEvents.length}
              >
                <Download size={16} /> Export normalized events
              </button>
              <button
                className="button button-secondary button-danger-subtle"
                onClick={() => {
                  setImported(null);
                  setImportError("");
                  onToast("Imported CloudTrail data cleared from this session.");
                }}
              >
                <Trash2 size={16} /> Clear session
              </button>
            </>
          ) : undefined
        }
      />

      <section className="local-processing-banner">
        <span>
          <ShieldCheck size={20} />
        </span>
        <div>
          <strong>Your log stays on this device</strong>
          <p>
            Parsing, validation, correlation, and export happen in this browser
            tab. Gatewatch does not upload or persist the original file.
          </p>
        </div>
        <span className="healthy-chip">
          <CircleCheck size={13} /> Session only
        </span>
      </section>

      <label
        className={`cloudtrail-dropzone ${
          dragging ? "cloudtrail-dropzone-active" : ""
        } ${processing ? "cloudtrail-dropzone-processing" : ""}`}
        htmlFor="cloudtrail-file-input"
        onDragEnter={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragOver={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={(event) => {
          if (!event.currentTarget.contains(event.relatedTarget as Node)) {
            setDragging(false);
          }
        }}
        onDrop={handleDrop}
      >
        <input
          id="cloudtrail-file-input"
          className="sr-only"
          type="file"
          accept=".json,.json.gz,application/json,application/gzip"
          disabled={processing}
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void processFile(file);
            event.target.value = "";
          }}
        />
        <span className="dropzone-icon">
          {processing ? (
            <RefreshCw size={27} className="spin" />
          ) : (
            <UploadCloud size={27} />
          )}
        </span>
        <div>
          <strong>
            {processing
              ? "Validating CloudTrail records…"
              : dragging
                ? "Drop the log to import it"
                : imported
                  ? "Drop another log to replace this session"
                  : "Drop a CloudTrail log here"}
          </strong>
          <p>
            Or choose a file · JSON or JSON.GZ · 25 MB compressed limit ·
            50,000 records
          </p>
        </div>
        <span className="button button-primary">
          <FileArchive size={16} /> Choose log
        </span>
      </label>

      {importError ? (
        <div className="import-error" role="alert">
          <CircleAlert size={17} />
          <div>
            <strong>CloudTrail import failed</strong>
            <p>{importError}</p>
          </div>
          <button
            aria-label="Dismiss import error"
            onClick={() => setImportError("")}
          >
            <X size={15} />
          </button>
        </div>
      ) : null}

      {imported ? (
        <>
          <section className="import-file-summary">
            <div className="imported-file">
              <span>
                <FileJson2 size={19} />
              </span>
              <p>
                <strong>{imported.fileName}</strong>
                <small>
                  {(imported.fileSize / 1024 / 1024).toFixed(2)} MB · imported{" "}
                  {new Date(imported.importedAt).toLocaleTimeString()}
                </small>
              </p>
            </div>
            <div>
              <strong>{imported.result.totalRecords.toLocaleString()}</strong>
              <span>Total records</span>
            </div>
            <div>
              <strong>{imported.result.events.length.toLocaleString()}</strong>
              <span>SG events</span>
            </div>
            <div className="import-danger-metric">
              <strong>{imported.result.internetWideChanges}</strong>
              <span>Internet-wide changes</span>
            </div>
            <div>
              <strong>{correlatedEvents}</strong>
              <span>Matched groups</span>
            </div>
          </section>

          {imported.result.warnings.length ? (
            <section className="import-warnings">
              {imported.result.warnings.map((warning) => (
                <p key={warning}>
                  <AlertTriangle size={14} /> {warning}
                </p>
              ))}
            </section>
          ) : null}

          <section className="panel imported-events-panel">
            <div className="imported-events-header">
              <div>
                <h2>Security-group change events</h2>
                <p>
                  {imported.result.skippedRecords.toLocaleString()} unrelated
                  CloudTrail records were ignored · {failedEvents} failed AWS
                  calls retained
                </p>
              </div>
              <div className="import-event-filters">
                <label className="table-search">
                  <Search size={15} />
                  <input
                    value={eventQuery}
                    onChange={(event) => {
                      setEventQuery(event.target.value);
                      setEventPage(1);
                    }}
                    placeholder="Search actor, group, CIDR…"
                    aria-label="Search imported CloudTrail events"
                  />
                </label>
                <label className="filter-select">
                  <Filter size={14} />
                  <select
                    value={effectFilter}
                    onChange={(event) => {
                      setEffectFilter(event.target.value);
                      setEventPage(1);
                    }}
                    aria-label="Filter imported events by effect"
                  >
                    <option value="all">All access effects</option>
                    <option value="Broadens access">Broadens access</option>
                    <option value="Restricts access">Restricts access</option>
                    <option value="Changes access">Changes access</option>
                    <option value="Lifecycle">Lifecycle</option>
                  </select>
                </label>
              </div>
            </div>
            <div className="import-results-count">
              Showing{" "}
              <strong>
                {visibleEvents.length
                  ? ((eventPage - 1) * eventsPerPage + 1).toLocaleString()
                  : 0}
                –
                {Math.min(
                  eventPage * eventsPerPage,
                  visibleEvents.length,
                ).toLocaleString()}
              </strong>{" "}
              of <strong>{visibleEvents.length.toLocaleString()}</strong> events
            </div>
            {visibleEvents.length ? (
              <div className="table-wrap cloudtrail-event-table">
                <table>
                  <thead>
                    <tr>
                      <th>Time / event</th>
                      <th>Security group</th>
                      <th>Access change</th>
                      <th>CIDR / service</th>
                      <th>Actor</th>
                      <th>AWS result</th>
                      <th>
                        <span className="sr-only">Open</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {pageEvents.map((event) => {
                      const linkedGroup = event.groupIds
                        .map((id) =>
                          securityGroups.find((group) => group.id === id),
                        )
                        .find(
                          (group): group is SecurityGroup => group !== undefined,
                        );
                      return (
                        <CloudTrailEventRow
                          key={event.id}
                          event={event}
                          linkedGroup={linkedGroup}
                          onSelect={onSelect}
                        />
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="empty-state">
                <div>
                  <Search size={24} />
                </div>
                <h3>No imported events match</h3>
                <p>Clear the search or choose another access-effect filter.</p>
                <button
                  className="button button-secondary"
                  onClick={() => {
                    setEventQuery("");
                    setEffectFilter("all");
                  }}
                >
                  Clear filters
                </button>
              </div>
            )}
            {visibleEvents.length > eventsPerPage ? (
              <div className="event-pagination" aria-label="Imported event pages">
                <button
                  className="button button-small"
                  onClick={() =>
                    setEventPage((current) => Math.max(1, current - 1))
                  }
                  disabled={eventPage === 1}
                >
                  Previous
                </button>
                <span>
                  Page <strong>{eventPage}</strong> of{" "}
                  <strong>{totalEventPages.toLocaleString()}</strong>
                </span>
                <button
                  className="button button-small"
                  onClick={() =>
                    setEventPage((current) =>
                      Math.min(totalEventPages, current + 1),
                    )
                  }
                  disabled={eventPage === totalEventPages}
                >
                  Next
                </button>
              </div>
            ) : null}
          </section>
        </>
      ) : (
        <div className="cloudtrail-onboarding-grid">
          <section className="panel">
            <span className="onboarding-icon">
              <Activity size={20} />
            </span>
            <h2>Supported security-group events</h2>
            <p>
              Authorize, revoke, modify, create, delete, and rule-description
              changes from EC2 CloudTrail management events.
            </p>
          </section>
          <section className="panel">
            <span className="onboarding-icon">
              <ExternalLink size={20} />
            </span>
            <h2>Broad-access detection</h2>
            <p>
              Changes containing `0.0.0.0/0` or `::/0` are highlighted without
              incorrectly claiming they are reachable.
            </p>
          </section>
          <section className="panel">
            <span className="onboarding-icon">
              <KeyRound size={20} />
            </span>
            <h2>Actor attribution</h2>
            <p>
              IAM identity, source IP, user agent, account, Region, request ID,
              and failed API calls remain available for investigation.
            </p>
          </section>
        </div>
      )}
    </>
  );
}

function CloudTrailEventRow({
  event,
  linkedGroup,
  onSelect,
}: {
  event: ImportedCloudTrailEvent;
  linkedGroup?: SecurityGroup;
  onSelect: (group: SecurityGroup) => void;
}) {
  const displayTime = event.eventTime
    ? new Date(event.eventTime).toLocaleString()
    : "Time unavailable";
  const groupLabel =
    linkedGroup?.name ?? event.groupIds.join(", ") ?? "Group not present";
  const actorLabel = event.actor.includes("/")
    ? event.actor.split("/").at(-1)
    : event.actor;
  return (
    <tr>
      <td>
        <strong className="cell-primary">{event.eventName}</strong>
        <small>{displayTime}</small>
      </td>
      <td>
        {linkedGroup ? (
          <button className="group-link compact-group-link" onClick={() => onSelect(linkedGroup)}>
            <span className={`resource-icon icon-${linkedGroup.severity}`}>
              <Network size={15} />
            </span>
            <span>
              <strong>{groupLabel}</strong>
              <small>{linkedGroup.id}</small>
            </span>
          </button>
        ) : (
          <>
            <strong className="cell-primary">
              {groupLabel || "Group ID unavailable"}
            </strong>
            <small>Not matched to current inventory</small>
          </>
        )}
      </td>
      <td>
        <span
          className={`event-effect effect-${event.effect
            .toLowerCase()
            .replaceAll(" ", "-")}`}
        >
          {event.effect === "Broadens access" ? (
            <AlertTriangle size={12} />
          ) : event.effect === "Restricts access" ? (
            <ShieldCheck size={12} />
          ) : (
            <Activity size={12} />
          )}
          {event.effect}
        </span>
        <small>{event.direction}</small>
      </td>
      <td>
        {event.cidrs.length ? (
          <div className="event-cidr-list">
            {event.cidrs.slice(0, 3).map((cidr) => (
              <code
                className={`cidr-chip ${
                  cidr === "0.0.0.0/0" || cidr === "::/0"
                    ? "cidr-public"
                    : ""
                }`}
                key={cidr}
              >
                {cidr}
              </code>
            ))}
          </div>
        ) : (
          <span className="muted-value">Not present</span>
        )}
        <small>
          {[event.protocol, event.ports].filter(Boolean).join(" · ") ||
            "Service not present"}
        </small>
      </td>
      <td>
        <strong className="cell-primary">{actorLabel}</strong>
        <small>
          {event.sourceIp || "Source unavailable"} · {event.actorType}
        </small>
      </td>
      <td>
        {event.errorCode ? (
          <span className="api-result api-result-failed">
            <X size={12} /> {event.errorCode}
          </span>
        ) : (
          <span className="api-result api-result-success">
            <Check size={12} /> Success
          </span>
        )}
        <small>{event.region || "Region unavailable"}</small>
      </td>
      <td>
        {linkedGroup ? (
          <button
            className="row-open"
            aria-label={`Investigate ${linkedGroup.name}`}
            onClick={() => onSelect(linkedGroup)}
          >
            <ChevronRight size={17} />
          </button>
        ) : null}
      </td>
    </tr>
  );
}

function HandoffsView({ onToast }: { onToast: (message: string) => void }) {
  const [selectedId, setSelectedId] = useState(awsHandoffs[0].id);
  const selected =
    awsHandoffs.find((handoff) => handoff.id === selectedId) ?? awsHandoffs[0];

  function generateHandoff() {
    const artifact = {
      schemaVersion: "2026-07-30",
      integration: selected.id,
      mode: selected.mode,
      generatedAt: new Date().toISOString(),
      dryRun: true,
      authorization: {
        awsCredentialsIncluded: false,
        writeExecutionEnabled: false,
        approvalRequired: selected.mode === "Approval required",
      },
      scope: {
        accounts: ["428196730552", "718345229104"],
        regions: ["us-east-1", "us-west-2"],
        policy: "production-database-boundary",
      },
      prerequisites: selected.prerequisites,
    };
    downloadText(
      `gatewatch-${selected.id}-handoff.json`,
      JSON.stringify(artifact, null, 2),
      "application/json",
    );
    onToast(`${selected.output} generated in dry-run mode.`);
  }

  return (
    <>
      <PageHeader
        eyebrow="Controlled AWS integration"
        title="Hand off analysis and enforcement safely."
        description="Generate reviewable AWS-native artifacts while keeping Gatewatch read-only by default. Enforcement requires explicit configuration and approval."
      />
      <section className="read-only-banner">
        <span>
          <ShieldCheck size={20} />
        </span>
        <div>
          <strong>Read-only control plane</strong>
          <p>
            No customer access keys are stored. Future AWS deployment uses
            scoped cross-account roles; all write paths remain disabled until
            individually approved.
          </p>
        </div>
        <span className="healthy-chip">
          <CircleCheck size={13} /> Safe default
        </span>
      </section>
      <div className="handoff-layout">
        <section className="integration-grid">
          {awsHandoffs.map((handoff) => (
            <button
              className={`panel integration-card ${
                selected.id === handoff.id ? "active" : ""
              }`}
              key={handoff.id}
              onClick={() => setSelectedId(handoff.id)}
            >
              <span className="integration-icon">
                {handoff.category === "Analyze" ? (
                  <Search size={19} />
                ) : handoff.category === "Enforce" ? (
                  <ShieldEllipsis size={19} />
                ) : handoff.category === "Change" ? (
                  <GitPullRequest size={19} />
                ) : (
                  <CloudCog size={19} />
                )}
              </span>
              <span>
                <em>{handoff.category}</em>
                <strong>{handoff.name}</strong>
                <small>{handoff.description}</small>
              </span>
              <span
                className={`integration-readiness readiness-${handoff.readiness
                  .toLowerCase()
                  .replaceAll(" ", "-")}`}
              >
                {handoff.readiness}
              </span>
            </button>
          ))}
        </section>
        <aside className="panel handoff-detail">
          <div>
            <span className="eyebrow">{selected.category} integration</span>
            <h2>{selected.name}</h2>
            <p>{selected.description}</p>
          </div>
          <dl>
            <div>
              <dt>Operating mode</dt>
              <dd>{selected.mode}</dd>
            </div>
            <div>
              <dt>Generated artifact</dt>
              <dd>{selected.output}</dd>
            </div>
            <div>
              <dt>Configuration state</dt>
              <dd>{selected.readiness}</dd>
            </div>
          </dl>
          <section>
            <h3>Prerequisites</h3>
            {selected.prerequisites.map((prerequisite) => (
              <p key={prerequisite}>
                <CircleCheck size={13} /> {prerequisite}
              </p>
            ))}
          </section>
          <div className="handoff-boundary">
            <ShieldAlert size={17} />
            <p>
              <strong>Execution boundary</strong>
              This version generates a dry-run artifact only. It cannot call
              AWS APIs or modify network policy.
            </p>
          </div>
          <button className="button button-primary" onClick={generateHandoff}>
            <Download size={16} /> Generate dry-run artifact
          </button>
        </aside>
      </div>
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
  const visibleActivity = connectivityEvents
    .filter((item) => channel === "all" || item.channel === channel)
    .slice(0, range === "7" ? 2 : undefined);

  return (
    <>
      <PageHeader
        eyebrow="Time-travel evidence"
        title="Connectivity history"
        description="Reconstruct when a path appeared or disappeared, who changed it, whether approval existed, and how business risk changed."
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
              <h2>Path-changing events</h2>
              <p>CloudTrail actors linked to Config graph snapshots</p>
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
                <article className="change-card connectivity-change-card" key={item.id}>
                  <span
                    className={`timeline-icon ${
                      item.authorization === "Approved"
                        ? "timeline-approved"
                        : "timeline-critical"
                    }`}
                  >
                    {item.authorization === "Approved" ? (
                      <Check size={16} />
                    ) : (
                      <Route size={16} />
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
                      {item.authorization !== "Approved" ? (
                        <span className="approval-chip">
                          {item.authorization}
                        </span>
                      ) : (
                        <span className="authorized-chip">
                          <Check size={11} /> {item.ticket}
                        </span>
                      )}
                    </div>
                    <button onClick={() => onSelect(group)}>
                      {item.title} · {item.application}
                    </button>
                    <p>
                      {item.actor} · {item.date} at {item.time}
                    </p>
                    <p className="connectivity-summary">{item.summary}</p>
                    <div className="inline-diff">
                      <span>
                        <em>Before snapshot</em>
                        {item.pathsBefore} paths · risk {item.riskBefore}
                      </span>
                      <ArrowRight size={15} />
                      <span>
                        <em>After snapshot</em>
                        {item.pathsAfter} paths · risk {item.riskAfter}
                      </span>
                    </div>
                  </div>
                  <code>{item.id.replace("evt-", "").slice(0, 8)}</code>
                </article>
              );
            })}
          </div>
        </section>
        <aside className="activity-side">
          <section className="panel event-summary">
            <h2>Graph change summary</h2>
            <div>
              <span>Paths created</span>
              <strong>29</strong>
            </div>
            <div>
              <span>Paths removed</span>
              <strong>14</strong>
            </div>
            <div>
              <span>Outside workflow</span>
              <strong>2</strong>
            </div>
            <div>
              <span>Expired intent</span>
              <strong>1</strong>
            </div>
          </section>
          <section className="panel source-note">
            <KeyRound size={20} />
            <h3>Historical confidence</h3>
            <p>
              Each point-in-time graph keeps configuration, supported path
              coverage, traffic window, authorization, and originating actor
              separate.
            </p>
            <span className="retention-chip">
              <CircleCheck size={13} /> 365-day graph retention
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
  inventorySource,
}: {
  onSync: () => void;
  syncing: boolean;
  inventorySource: AwsInventorySource | null;
}) {
  const coverage = inventorySource?.coveragePercent ?? 0;
  const freshness = inventorySource ? `${inventorySource.freshnessMinutes} min ago` : "not connected";
  const sources = [
    {
      name: "EC2 inventory collector",
      detail: "Security groups, rules, attachments, routes, network ACLs, and public addresses",
      status: inventorySource?.complete ? "Healthy" : inventorySource ? "Partial" : "Not connected",
      coverage: `${coverage}%`,
      time: freshness,
      icon: Database,
    },
    {
      name: "CloudTrail attribution",
      detail: "Security-group management events and caller identity",
      status: "Not connected",
      coverage: "0%",
      time: "not available",
      icon: Activity,
    },
    {
      name: "VPC Flow Logs",
      detail: "Accepted and rejected traffic for attached ENIs",
      status: "Not connected",
      coverage: "0%",
      time: "not available",
      icon: Radio,
    },
    {
      name: "Inspector + Security Hub",
      detail: "Vulnerability and asset-criticality context",
      status: "Not connected",
      coverage: "0%",
      time: "not available",
      icon: ShieldAlert,
    },
    {
      name: "Terraform access manifests",
      detail: "Approved application connectivity and ticket intent",
      status: "Not connected",
      coverage: "0%",
      time: "not available",
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
          <strong>{inventorySource ? "AWS evidence snapshot loaded" : "AWS evidence is not connected"}</strong>
          <p>
            {inventorySource
              ? `${inventorySource.accountCount} of ${inventorySource.accountsExpected} accounts and ${inventorySource.regionCount} of ${inventorySource.regionsExpected} account-regions were collected. Traffic, change attribution, vulnerability, and intent sources are reported separately.`
              : "Connect the read-only AWS collector to replace demonstration records with account-scoped evidence."}
          </p>
        </div>
        <em>{coverage}% collection coverage</em>
      </section>
      <OrganizationCoveragePanel
        legacy={inventorySource}
        refreshSignal={syncing}
      />
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
              <strong>{inventorySource ? `${inventorySource.accountCount} of ${inventorySource.accountsExpected}` : "Not connected"}</strong>
              <small>Authenticated accounts</small>
            </div>
            <div>
              <span>Regions</span>
              <strong>{inventorySource ? `${inventorySource.regionCount} of ${inventorySource.regionsExpected}` : "Not connected"}</strong>
              <small>Scanned account-regions</small>
            </div>
            <div>
              <span>Evaluation</span>
              <strong>{inventorySource ? `${inventorySource.freshnessMinutes} min old` : "Unavailable"}</strong>
              <small>Latest snapshot freshness</small>
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
        <section className="panel trust-panel">
          <div className="panel-header">
            <div>
              <h2>Confidence boundaries</h2>
              <p>Coverage gaps that constrain finding certainty</p>
            </div>
            <span className="scope-state scope-state-attention">4 gaps</span>
          </div>
          <div className="trust-gap-list">
            <div>
              <span className="meaning-icon meaning-deny">
                <AlertTriangle size={14} />
              </span>
              <p>
                <strong>Flow Logs are not connected</strong>
                Absence of traffic is never treated as proof of non-use.
              </p>
              <em>Medium impact</em>
            </div>
            <div>
              <span className="meaning-icon">
                <Braces size={14} />
              </span>
              <p>
                <strong>Attribution, vulnerabilities, and intent are incomplete</strong>
                Findings preserve these unknowns instead of inferring authorization or change provenance.
              </p>
              <em>High impact</em>
            </div>
          </div>
          <div className="evidence-semantics compact-semantics">
            {[
              ["Configured", "AWS Config"],
              ["Reachable", "Static analysis"],
              ["Observed", "Flow Logs"],
              ["Attributed", "CloudTrail"],
              ["Authorized", "Access policy"],
              ["Complete", "Coverage health"],
            ].map(([label, source]) => (
              <span key={label}>
                <Check size={12} />
                <strong>{label}</strong>
                <small>{source}</small>
              </span>
            ))}
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
