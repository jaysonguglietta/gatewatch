"use client";

import {
  AlertTriangle,
  BadgeCheck,
  BellRing,
  CalendarClock,
  Check,
  CheckCheck,
  ChevronLeft,
  ChevronRight,
  ChevronsUpDown,
  CircleAlert,
  CircleCheck,
  Clock3,
  Download,
  Clipboard,
  Columns3,
  Command,
  ExternalLink,
  FileCheck2,
  Filter,
  FolderTree,
  History,
  ListChecks,
  Layers3,
  Network,
  NotebookPen,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldEllipsis,
  ShieldX,
  SlidersHorizontal,
  TicketPlus,
  UserRound,
  Users,
  X,
} from "lucide-react";
import { csvDocument } from "../lib/csv";
import { useEffect, useMemo, useRef, useState } from "react";
import type {
  DailyFinding,
  FindingWorkflowStatus,
} from "../lib/daily-findings";

type Filters = {
  q: string;
  severity: string;
  status: string;
  ou: string;
  account: string;
  region: string;
  owner: string;
  environment: string;
  internet: string;
  sort: string;
  mine: string;
};

type SavedView = {
  id: string;
  name: string;
  filters: Partial<Filters>;
  isDefault: boolean;
  visibility?: "personal" | "team";
  owner?: string;
};

type FindingHistoryEvent = {
  id: number;
  eventType: string;
  fromStatus: string;
  toStatus: string;
  actor: string;
  assignee: string;
  note: string;
  ticketRef: string;
  dueAt: string;
  expiresAt: string;
  compensatingControls: string[];
  createdAt: string;
  reasonCode?: string;
};

type InboxResponse = {
  items: DailyFinding[];
  total: number;
  page: number;
  pageSize: number;
  pageCount: number;
  stats: {
    newToday: number;
    awaitingAction: number;
    overdue: number;
    expiringSoon: number;
    reopened: number;
    staleAccounts: number;
    reviewedToday: number;
  };
  coverage: {
    accounts: number;
    organizationalUnits: number;
    regions: number;
    staleAccounts: number;
  };
  facets: {
    organizationalUnits: string[];
    accounts: { id: string; name: string }[];
    regions: string[];
    owners: string[];
  };
  savedViews: SavedView[];
  source: {
    mode: "aws" | "demonstration";
    snapshotId: string;
    generatedAt: string;
    complete: boolean;
    coveragePercent: number;
    freshnessMinutes: number;
  };
  currentUser: string;
};

type TriageAction = "follow-up" | "acknowledged" | "accepted-risk" | "resolved";
type QueueMode = "findings" | "security-groups";
type QueueDensity = "compact" | "comfortable";

const defaultFilters: Filters = {
  q: "",
  severity: "",
  status: "open",
  ou: "",
  account: "",
  region: "",
  owner: "",
  environment: "",
  internet: "",
  sort: "risk",
  mine: "",
};

const systemViews: SavedView[] = [
  {
    id: "system-mine",
    name: "Assigned to me",
    filters: { mine: "1", status: "open", sort: "risk" },
    isDefault: false,
  },
  {
    id: "system-daily",
    name: "Daily critical review",
    filters: { severity: "critical", status: "open", sort: "risk" },
    isDefault: false,
  },
  {
    id: "system-internet",
    name: "Internet reachable",
    filters: { internet: "internet", status: "open", sort: "risk" },
    isDefault: false,
  },
  {
    id: "system-production",
    name: "Production exposure",
    filters: { environment: "Production", status: "open", sort: "risk" },
    isDefault: false,
  },
  {
    id: "system-follow-up",
    name: "Follow-ups",
    filters: { status: "follow-up", sort: "updated" },
    isDefault: false,
  },
  {
    id: "system-exceptions",
    name: "Accepted risk",
    filters: { status: "accepted-risk", sort: "updated" },
    isDefault: false,
  },
];

const statusLabels: Record<FindingWorkflowStatus, string> = {
  new: "New",
  "follow-up": "Follow-up",
  acknowledged: "Acknowledged",
  "accepted-risk": "Accepted risk",
  reopened: "Reopened",
  resolved: "Resolved",
};

function initialFilters() {
  if (typeof window === "undefined") return defaultFilters;
  const params = new URLSearchParams(window.location.search);
  return {
    q: params.get("q") ?? "",
    severity: params.get("severity") ?? "",
    status: params.get("status") ?? "open",
    ou: params.get("ou") ?? "",
    account: params.get("account") ?? "",
    region: params.get("region") ?? "",
    owner: params.get("owner") ?? "",
    environment: params.get("environment") ?? "",
    internet: params.get("internet") ?? "",
    sort: params.get("sort") ?? "risk",
    mine: params.get("mine") ?? "",
  };
}

function riskTone(score: number) {
  if (score >= 85) return "critical";
  if (score >= 70) return "high";
  if (score >= 45) return "medium";
  return "low";
}

function decisionEligible(finding: DailyFinding, source: InboxResponse["source"] | undefined) {
  return (
    finding.evidence.state === "observed" &&
    finding.evidence.confidence >= 70 &&
    (!source || source.mode === "demonstration" || (source.complete && source.freshnessMinutes <= 1_440))
  );
}

function awsConsoleLinks(finding: DailyFinding) {
  const base = `https://${finding.region}.console.aws.amazon.com`;
  return {
    securityGroup: `${base}/ec2/home?region=${encodeURIComponent(finding.region)}#SecurityGroup:groupId=${encodeURIComponent(finding.securityGroupId)}`,
    cloudTrail: `${base}/cloudtrailv2/home?region=${encodeURIComponent(finding.region)}#/events?EventId=${encodeURIComponent(finding.changeEventId)}`,
    config: `${base}/config/home?region=${encodeURIComponent(finding.region)}#/resources/details?resourceId=${encodeURIComponent(finding.securityGroupId)}&resourceType=AWS::EC2::SecurityGroup`,
  };
}

function formatDate(value: string) {
  if (!value) return "Not set";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : new Intl.DateTimeFormat("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
      }).format(parsed);
}

function downloadCsv(items: DailyFinding[]) {
  const rows = [
    [
      "Finding",
      "Security group",
      "Account",
      "OU",
      "Region",
      "Severity",
      "Risk",
      "Verdict",
      "Status",
      "Assignee",
      "Note",
      "Ticket",
      "Due",
      "Exception expires",
    ],
    ...items.map((item) => [
      item.title,
      item.securityGroupName,
      `${item.accountName} (${item.accountId})`,
      item.organizationalUnit,
      item.region,
      item.severity,
      String(item.riskScore),
      item.verdict,
      statusLabels[item.status],
      item.assignee,
      item.note,
      item.ticketRef,
      item.dueAt,
      item.expiresAt,
    ]),
  ];
  const content = csvDocument(rows);
  const url = URL.createObjectURL(new Blob([content], { type: "text/csv" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "gatewatch-daily-findings.csv";
  link.click();
  URL.revokeObjectURL(url);
}

export default function DailyFindingsView({
  onOpenGroup,
  onToast,
  globalQuery,
  onGlobalQueryChange,
}: {
  onOpenGroup: (securityGroupId: string) => void;
  onToast: (message: string) => void;
  globalQuery?: string;
  onGlobalQueryChange?: (value: string) => void;
}) {
  const [filters, setFilters] = useState<Filters>(initialFilters);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [data, setData] = useState<InboxResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [activeFinding, setActiveFinding] = useState<DailyFinding | null>(null);
  const [action, setAction] = useState<TriageAction | null>(null);
  const [actionTargets, setActionTargets] = useState<string[]>([]);
  const [refreshKey, setRefreshKey] = useState(0);
  const [saveViewOpen, setSaveViewOpen] = useState(false);
  const [viewName, setViewName] = useState("");
  const [viewDefault, setViewDefault] = useState(false);
  const [viewVisibility, setViewVisibility] = useState<"personal" | "team">("personal");
  const [activeViewId, setActiveViewId] = useState("");
  const [deleteViewOpen, setDeleteViewOpen] = useState(false);
  const [jiraOpen, setJiraOpen] = useState(false);
  const [queueMode, setQueueMode] = useState<QueueMode>("findings");
  const [density, setDensity] = useState<QueueDensity>(() => {
    if (typeof window === "undefined") return "compact";
    const stored = window.localStorage.getItem("gatewatch.findings-density");
    return stored === "comfortable" ? "comfortable" : "compact";
  });
  const [visibleFields, setVisibleFields] = useState(() => {
    const defaults = { scope: true, rule: true, workflow: true };
    if (typeof window === "undefined") return defaults;
    try {
      return { ...defaults, ...JSON.parse(window.localStorage.getItem("gatewatch.findings-fields") ?? "{}") } as typeof defaults;
    } catch {
      return defaults;
    }
  });
  const [reviewedInSession, setReviewedInSession] = useState(0);
  const [undo, setUndo] = useState<{ token: string; expiresAt: string; count: number } | null>(null);
  const requestId = useRef(0);
  const defaultViewApplied = useRef(false);


  const queryString = useMemo(() => {
    const params = new URLSearchParams();
    const effectiveFilters = {
      ...filters,
      q: globalQuery || filters.q,
    };
    Object.entries(effectiveFilters).forEach(([key, value]) => {
      if (value) params.set(key, value);
    });
    params.set("page", String(page));
    params.set("pageSize", String(pageSize));
    return params.toString();
  }, [filters, globalQuery, page, pageSize]);

  useEffect(() => {
    const currentRequest = ++requestId.current;
    const timer = window.setTimeout(() => {
      setLoading(true);
      setError("");
      fetch(`/api/findings?${queryString}`)
        .then(async (response) => {
          const payload = (await response.json()) as InboxResponse & { error?: string };
          if (!response.ok) throw new Error(payload.error ?? "The inbox is unavailable.");
          return payload;
        })
        .then((payload) => {
          if (currentRequest !== requestId.current) return;
          const defaultView = payload.savedViews.find((view) => view.isDefault);
          if (
            !defaultViewApplied.current &&
            defaultView &&
            !window.location.search
          ) {
            defaultViewApplied.current = true;
            setActiveViewId(defaultView.id);
            setFilters({ ...defaultFilters, ...defaultView.filters });
            onGlobalQueryChange?.(defaultView.filters.q ?? "");
          }
          setData(payload);
          setPage(payload.page);
          setSelected((current) => {
            const visible = new Set(payload.items.map((item) => item.fingerprint));
            return new Set([...current].filter((fingerprint) => visible.has(fingerprint)));
          });
          setActiveFinding((current) =>
            current
              ? payload.items.find(
                  (item) => item.fingerprint === current.fingerprint,
                ) ?? payload.items[0] ?? null
              : payload.items[0] ?? null,
          );
        })
        .catch((caught) => {
          if (currentRequest === requestId.current) {
            setError(caught instanceof Error ? caught.message : "The inbox is unavailable.");
          }
        })
        .finally(() => {
          if (currentRequest === requestId.current) setLoading(false);
        });
    }, 0);
    return () => window.clearTimeout(timer);
  }, [onGlobalQueryChange, queryString, refreshKey]);

  useEffect(() => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => {
      if (value && !(key === "status" && value === "open")) params.set(key, value);
    });
    const next = params.toString();
    window.history.replaceState(
      {},
      "",
      `${window.location.pathname}${next ? `?${next}` : ""}`,
    );
  }, [filters]);

  function updateFilter<K extends keyof Filters>(key: K, value: Filters[K]) {
    setFilters((current) => ({ ...current, [key]: value }));
    setPage(1);
    setSelected(new Set());
  }

  function openAction(nextAction: TriageAction, fingerprints: string[]) {
    setActionTargets(fingerprints);
    setAction(nextAction);
  }

  function applySavedView(view: SavedView) {
    setFilters({ ...defaultFilters, ...view.filters });
    onGlobalQueryChange?.(view.filters.q ?? "");
    setPage(1);
    setSelected(new Set());
    onToast(`${view.name} applied.`);
  }

  async function saveView() {
    const response = await fetch("/api/findings", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        action: "save-view",
        name: viewName,
        filters,
        isDefault: viewDefault,
        visibility: viewVisibility,
      }),
    });
    const payload = (await response.json()) as { saved?: boolean; error?: string };
    if (!response.ok || !payload.saved) {
      setError(payload.error ?? "The view could not be saved.");
      return;
    }
    setSaveViewOpen(false);
    setViewName("");
    setViewDefault(false);
    setViewVisibility("personal");
    setRefreshKey((value) => value + 1);
    onToast("Saved view is available in the daily inbox.");
  }

  async function deleteView() {
    const response = await fetch("/api/findings", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "delete-view", id: activeViewId }),
    });
    const payload = (await response.json()) as { deleted?: boolean; error?: string };
    if (!response.ok || !payload.deleted) {
      setError(payload.error ?? "The saved view could not be deleted.");
      return;
    }
    setDeleteViewOpen(false);
    setActiveViewId("");
    setRefreshKey((value) => value + 1);
    onToast("Saved view deleted.");
  }

  const allVisibleSelected =
    Boolean(data?.items.length) &&
    data!.items.every((item) => selected.has(item.fingerprint));

  const clusters = useMemo(() => {
    const grouped = new Map<string, DailyFinding[]>();
    for (const finding of data?.items ?? []) {
      const current = grouped.get(finding.canonicalResourceKey) ?? [];
      current.push(finding);
      grouped.set(finding.canonicalResourceKey, current);
    }
    return [...grouped.values()].sort(
      (left, right) => Math.max(...right.map((item) => item.riskScore)) - Math.max(...left.map((item) => item.riskScore)),
    );
  }, [data?.items]);

  function moveActive(offset: number) {
    if (!data?.items.length) return;
    const index = activeFinding
      ? data.items.findIndex((item) => item.fingerprint === activeFinding.fingerprint)
      : -1;
    const nextIndex = Math.min(data.items.length - 1, Math.max(0, index + offset));
    setActiveFinding(data.items[nextIndex]);
  }

  async function undoLastDecision() {
    if (!undo) return;
    const response = await fetch("/api/findings", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "undo", token: undo.token }),
    });
    const payload = (await response.json()) as { updated?: number; error?: string };
    if (!response.ok || !payload.updated) {
      setError(payload.error ?? "The last decision could not be undone.");
      setUndo(null);
      return;
    }
    setReviewedInSession((value) => Math.max(0, value - undo.count));
    setUndo(null);
    setRefreshKey((value) => value + 1);
    onToast("The previous triage decision was reverted.");
  }

  useEffect(() => {
    function handleKeyboard(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      if (target?.closest("input, textarea, select, [contenteditable='true']")) return;
      if (action || saveViewOpen || deleteViewOpen || jiraOpen) return;
      const key = event.key.toLowerCase();
      if (key === "j") moveActive(1);
      else if (key === "k") moveActive(-1);
      else if (key === "f" && activeFinding) openAction("follow-up", [activeFinding.fingerprint]);
      else if (key === "a" && activeFinding) openAction("acknowledged", [activeFinding.fingerprint]);
      else if (key === "e" && activeFinding) openAction("accepted-risk", [activeFinding.fingerprint]);
      else if (key === "r" && activeFinding) openAction("resolved", [activeFinding.fingerprint]);
      else if (key === "escape") setActiveFinding(null);
      else if (key === "?") onToast("Shortcuts: J/K navigate · F follow-up · A acknowledge · E accept risk · R resolve · Esc close detail");
    }
    window.addEventListener("keydown", handleKeyboard);
    return () => window.removeEventListener("keydown", handleKeyboard);
  });

  return (
    <>
      <div className="daily-page-header">
        <div>
          <p className="eyebrow">Daily security operations</p>
          <h1>Daily findings inbox</h1>
          <p>
            Review what changed, assign follow-up, document acceptable exposure,
            and preserve a complete decision history across the AWS Organization.
          </p>
        </div>
        <div className="daily-header-actions">
          <button
            className="button button-secondary"
            onClick={() => {
              if (data) downloadCsv(data.items);
              onToast("Visible findings exported.");
            }}
          >
            <Download size={15} /> Export page
          </button>
          <button
            className="button button-primary"
            onClick={() => setRefreshKey((value) => value + 1)}
            disabled={loading}
          >
            <RefreshCw size={15} className={loading ? "spin" : ""} />
            Refresh evidence
          </button>
        </div>
      </div>

      <section className="daily-scope-bar" aria-label="Organization scope">
        <div className="scope-organization">
          <FolderTree size={17} />
          <p>
            <span>Organization</span>
            <strong>
              {data?.items[0]?.organization ??
                (data?.source.mode === "aws" ? "AWS account scope" : "Demonstration organization")}
            </strong>
          </p>
        </div>
        <label>
          <span>Organizational unit</span>
          <select
            value={filters.ou}
            onChange={(event) => updateFilter("ou", event.target.value)}
          >
            <option value="">All organizational units</option>
            {data?.facets.organizationalUnits.map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <label>
          <span>AWS account</span>
          <select
            value={filters.account}
            onChange={(event) => updateFilter("account", event.target.value)}
          >
            <option value="">All accounts</option>
            {data?.facets.accounts.map((account) => (
              <option value={account.id} key={account.id}>
                {account.name} · {account.id}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Region</span>
          <select
            value={filters.region}
            onChange={(event) => updateFilter("region", event.target.value)}
          >
            <option value="">All regions</option>
            {data?.facets.regions.map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
        <div className="coverage-scope">
          <strong>{data?.coverage.accounts ?? "—"}</strong>
          <span>accounts monitored</span>
          {data?.source ? (
            <small>
              {data.source.mode === "aws"
                ? `${data.source.coveragePercent}% collected · ${data.source.freshnessMinutes}m old`
                : "Demonstration data"}
            </small>
          ) : null}
        </div>
      </section>

      <section className="daily-stat-grid" aria-label="Daily workload summary">
        <button onClick={() => updateFilter("status", "new")}>
          <span className="daily-stat-icon stat-new"><BellRing size={17} /></span>
          <p><strong>{data?.stats.newToday ?? "—"}</strong><span>New today</span><small>Since your last review</small></p>
        </button>
        <button onClick={() => updateFilter("status", "open")}>
          <span className="daily-stat-icon stat-action"><ShieldAlert size={17} /></span>
          <p><strong>{data?.stats.awaitingAction ?? "—"}</strong><span>Awaiting action</span><small>New or reopened</small></p>
        </button>
        <button onClick={() => updateFilter("status", "follow-up")}>
          <span className="daily-stat-icon stat-overdue"><CalendarClock size={17} /></span>
          <p><strong>{data?.stats.overdue ?? "—"}</strong><span>Follow-ups overdue</span><small>Owner action required</small></p>
        </button>
        <button onClick={() => updateFilter("status", "accepted-risk")}>
          <span className="daily-stat-icon stat-exception"><ShieldEllipsis size={17} /></span>
          <p><strong>{data?.stats.expiringSoon ?? "—"}</strong><span>Exceptions expiring</span><small>Within 14 days</small></p>
        </button>
        <button onClick={() => updateFilter("status", "reopened")}>
          <span className="daily-stat-icon stat-reopened"><History size={17} /></span>
          <p><strong>{data?.stats.reopened ?? "—"}</strong><span>Reopened</span><small>Exposure returned</small></p>
        </button>
        <button onClick={() => onToast("Coverage view opened from the sidebar.")}>
          <span className="daily-stat-icon stat-stale"><CircleAlert size={17} /></span>
          <p><strong>{data?.stats.staleAccounts ?? "—"}</strong><span>Accounts stale</span><small>Evidence older than SLA</small></p>
        </button>
      </section>

      <section className="panel daily-inbox-panel">
        <div className="saved-view-row">
          <label className="saved-view-picker">
            <ListChecks size={15} />
            <span>Saved view</span>
            <select
              value={activeViewId}
              onChange={(event) => {
                setActiveViewId(event.target.value);
                const view = [...systemViews, ...(data?.savedViews ?? [])].find(
                  (item) => item.id === event.target.value,
                );
                if (view) applySavedView(view);
              }}
            >
              <option value="">Choose a view</option>
              <optgroup label="Gatewatch views">
                {systemViews.map((view) => (
                  <option value={view.id} key={view.id}>{view.name}</option>
                ))}
              </optgroup>
              {data?.savedViews.length ? (
                <optgroup label="Personal and team views">
                  {data.savedViews.map((view) => (
                    <option value={view.id} key={view.id}>
                      {view.name}{view.visibility === "team" ? " · Team" : ""}{view.isDefault ? " · Default" : ""}
                    </option>
                  ))}
                </optgroup>
              ) : null}
            </select>
          </label>
          <button className="button button-secondary" onClick={() => setSaveViewOpen(true)}>
            <Save size={14} /> Save current view
          </button>
          {data && activeViewId && !activeViewId.startsWith("system-") && data.savedViews.find((view) => view.id === activeViewId)?.owner === data.currentUser ? (
            <button className="button button-secondary" onClick={() => setDeleteViewOpen(true)}>
              <X size={14} /> Delete view
            </button>
          ) : null}
          <span className="shareable-view">
            <Check size={13} /> Filters are reflected in the URL
          </span>
        </div>

        <div className="daily-filter-grid">
          <label className="daily-search">
            <Search size={16} />
            <input
              value={globalQuery || filters.q}
              onChange={(event) => {
                updateFilter("q", event.target.value);
                onGlobalQueryChange?.(event.target.value);
              }}
              placeholder="Search finding, security group, account, owner…"
              aria-label="Search daily findings"
            />
          </label>
          <label className="filter-select">
            <ShieldAlert size={14} />
            <select
              value={filters.severity}
              onChange={(event) => updateFilter("severity", event.target.value)}
              aria-label="Filter findings by severity"
            >
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </label>
          <label className="filter-select">
            <SlidersHorizontal size={14} />
            <select
              value={filters.status}
              onChange={(event) => updateFilter("status", event.target.value)}
              aria-label="Filter findings by workflow status"
            >
              <option value="open">All open findings</option>
              <option value="">Every status</option>
              <option value="new">New</option>
              <option value="reopened">Reopened</option>
              <option value="follow-up">Follow-up</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="accepted-risk">Accepted risk</option>
              <option value="resolved">Resolved</option>
            </select>
          </label>
          <label className="filter-select">
            <Users size={14} />
            <select
              value={filters.owner}
              onChange={(event) => updateFilter("owner", event.target.value)}
              aria-label="Filter findings by owner"
            >
              <option value="">All owners</option>
              {data?.facets.owners.map((owner) => (
                <option key={owner}>{owner}</option>
              ))}
            </select>
          </label>
          <label className="filter-select">
            <Network size={14} />
            <select
              value={filters.internet}
              onChange={(event) => updateFilter("internet", event.target.value)}
              aria-label="Filter findings by effective internet exposure"
            >
              <option value="">All internet states</option>
              <option value="internet">Internet path confirmed</option>
              <option value="no-internet">No internet path confirmed</option>
              <option value="unknown">Evidence incomplete</option>
            </select>
          </label>
          <label className="filter-select">
            <Filter size={14} />
            <select
              value={filters.environment}
              onChange={(event) => updateFilter("environment", event.target.value)}
              aria-label="Filter findings by environment"
            >
              <option value="">All environments</option>
              <option>Production</option>
              <option>Shared</option>
              <option>Staging</option>
              <option>Development</option>
            </select>
          </label>
          <label className="filter-select">
            <select
              value={filters.sort}
              onChange={(event) => updateFilter("sort", event.target.value)}
              aria-label="Sort daily findings"
            >
              <option value="risk">Risk: high to low</option>
              <option value="internet-first">Exposure: internet first</option>
              <option value="no-internet-first">Exposure: no internet first</option>
              <option value="age">Oldest first</option>
              <option value="updated">Recently reviewed</option>
              <option value="account">Account name</option>
            </select>
          </label>
        </div>

        {selected.size ? (
          <div className="bulk-action-bar" role="toolbar" aria-label="Bulk findings actions">
            <strong>{selected.size} selected</strong>
            <button onClick={() => openAction("follow-up", [...selected])}><CalendarClock size={14} />Create follow-up</button>
            <button disabled={data?.items.filter((item) => selected.has(item.fingerprint)).some((item) => !decisionEligible(item, data.source))} title="Decisions require complete, fresh observed evidence." onClick={() => openAction("acknowledged", [...selected])}><CheckCheck size={14} />Acknowledge</button>
            <button disabled={selected.size > 20 || data?.items.filter((item) => selected.has(item.fingerprint)).some((item) => !decisionEligible(item, data.source))} title="Accept risk is limited to 20 findings with complete evidence." onClick={() => openAction("accepted-risk", [...selected])}><ShieldEllipsis size={14} />Accept risk</button>
            <button disabled={data?.items.filter((item) => selected.has(item.fingerprint)).some((item) => !decisionEligible(item, data.source))} title="Resolution requires complete, fresh observed evidence." onClick={() => openAction("resolved", [...selected])}><ShieldX size={14} />Resolve</button>
            <button
              disabled={selected.size > 20}
              title={selected.size > 20 ? "Create tickets in batches of 20 findings or fewer." : undefined}
              onClick={() => setJiraOpen(true)}
            ><TicketPlus size={14} />Create Jira tickets</button>
            <button className="bulk-clear" onClick={() => setSelected(new Set())}><X size={14} />Clear</button>
          </div>
        ) : null}

        {error ? (
          <div className="daily-error" role="alert">
            <CircleAlert size={16} />
            <p><strong>Findings could not be loaded</strong><span>{error}</span></p>
            <button onClick={() => setRefreshKey((value) => value + 1)}>Try again</button>
          </div>
        ) : null}

        <div className="daily-result-summary">
          <span><strong>{data?.total ?? 0}</strong> findings · <b>{data?.stats.reviewedToday ?? 0}</b> reviewed today · <b>{reviewedInSession}</b> this session</span>
          <div className="queue-display-controls" aria-label="Queue display controls">
            <button className={queueMode === "findings" ? "active" : ""} onClick={() => setQueueMode("findings")}><ListChecks size={13} /> Findings</button>
            <button className={queueMode === "security-groups" ? "active" : ""} onClick={() => setQueueMode("security-groups")}><Layers3 size={13} /> Grouped</button>
            <button
              title="Toggle queue density"
              onClick={() => {
                const next = density === "compact" ? "comfortable" : "compact";
                setDensity(next);
                window.localStorage.setItem("gatewatch.findings-density", next);
              }}
            ><Columns3 size={13} /> {density === "compact" ? "Compact" : "Comfortable"}</button>
            <details className="queue-column-menu"><summary><ChevronsUpDown size={13} /> Fields</summary><div>{(["scope", "rule", "workflow"] as const).map((field) => <label key={field}><input type="checkbox" checked={visibleFields[field]} onChange={(event) => {
              const next = { ...visibleFields, [field]: event.target.checked };
              setVisibleFields(next);
              window.localStorage.setItem("gatewatch.findings-fields", JSON.stringify(next));
            }} />{field === "scope" ? "Account and region" : field === "rule" ? "Violating rule" : "Workflow state"}</label>)}</div></details>
            <span><Command size={12} /> J/K to review</span>
          </div>
        </div>

        {loading && !data ? (
          <div className="daily-loading" aria-label="Loading findings">
            {[0, 1, 2, 3, 4].map((value) => <span key={value} />)}
          </div>
        ) : data?.items.length ? (
          <div className={`triage-workspace density-${density}`}>
            <section className="triage-queue" aria-label="Findings review queue">
              <header className="triage-queue-header">
                <label>
                  <input
                    type="checkbox"
                    aria-label="Select all visible findings"
                    checked={allVisibleSelected}
                    onChange={(event) => setSelected(event.target.checked ? new Set(data.items.map((item) => item.fingerprint)) : new Set())}
                  />
                  Select page
                </label>
                <span>{queueMode === "findings" ? `${data.items.length} findings` : `${clusters.length} security groups`}</span>
              </header>
              <div className="triage-queue-scroll">
                {queueMode === "findings" ? data.items.map((item) => (
                  <article
                    key={item.fingerprint}
                    className={`triage-queue-item ${activeFinding?.fingerprint === item.fingerprint ? "active" : ""} ${selected.has(item.fingerprint) ? "selected" : ""}`}
                    onClick={() => setActiveFinding(item)}
                  >
                    <label onClick={(event) => event.stopPropagation()}>
                      <input type="checkbox" aria-label={`Select ${item.title}`} checked={selected.has(item.fingerprint)} onChange={(event) => setSelected((current) => {
                        const next = new Set(current);
                        if (event.target.checked) next.add(item.fingerprint); else next.delete(item.fingerprint);
                        return next;
                      })} />
                    </label>
                    <div className="queue-item-content">
                      <header><span className={`daily-severity severity-${item.severity}`} /><strong>{item.title}</strong><span className={`compact-risk risk-${riskTone(item.riskScore)}`}>{item.riskScore}</span></header>
                      <p>{item.securityGroupName} <code>{item.securityGroupId}</code></p>
                      {visibleFields.scope ? <small>{item.accountName} · {item.region}</small> : null}
                      {visibleFields.rule ? <div className="queue-rule"><Network size={12} /><span>{item.ruleSummary}</span></div> : null}
                      {visibleFields.workflow ? <footer><span className={`finding-status status-${item.status}`}>{statusLabels[item.status]}</span><span>{item.verdict}</span><span>{item.ageDays === 0 ? "Today" : `${item.ageDays}d old`}</span></footer> : null}
                    </div>
                  </article>
                )) : clusters.map((cluster) => {
                  const lead = cluster[0];
                  const allSelected = cluster.every((item) => selected.has(item.fingerprint));
                  return <article key={lead.canonicalResourceKey} className={`triage-cluster ${activeFinding && cluster.some((item) => item.fingerprint === activeFinding.fingerprint) ? "active" : ""}`}>
                    <header onClick={() => setActiveFinding(lead)}>
                      <label onClick={(event) => event.stopPropagation()}><input type="checkbox" checked={allSelected} aria-label={`Select all findings for ${lead.securityGroupName}`} onChange={(event) => setSelected((current) => {
                        const next = new Set(current);
                        cluster.forEach((item) => event.target.checked ? next.add(item.fingerprint) : next.delete(item.fingerprint));
                        return next;
                      })} /></label>
                      <div><strong>{lead.securityGroupName}</strong><code>{lead.securityGroupId}</code><small>{lead.accountName} · {lead.region} · {lead.attachments.length} resources</small></div>
                      <span className={`compact-risk risk-${riskTone(Math.max(...cluster.map((item) => item.riskScore)))}`}>{Math.max(...cluster.map((item) => item.riskScore))}</span>
                    </header>
                    <div className="cluster-findings">{cluster.map((item) => <button key={item.fingerprint} onClick={() => setActiveFinding(item)}><span className={`daily-severity severity-${item.severity}`} />{item.title}<ChevronRight size={13} /></button>)}</div>
                    <footer><span>{cluster.length} correlated findings</span><button onClick={() => { setSelected(new Set(cluster.map((item) => item.fingerprint))); openAction("follow-up", cluster.map((item) => item.fingerprint)); }}>Follow up as group</button></footer>
                  </article>;
                })}
              </div>
            </section>
            {activeFinding ? (
              <FindingInvestigationPane
                finding={activeFinding}
                source={data.source}
                position={data.items.findIndex((item) => item.fingerprint === activeFinding.fingerprint) + 1}
                total={data.items.length}
                onPrevious={() => moveActive(-1)}
                onNext={() => moveActive(1)}
                onClose={() => setActiveFinding(null)}
                onOpenGroup={() => onOpenGroup(activeFinding.securityGroupId)}
                onAction={(nextAction) => openAction(nextAction, [activeFinding.fingerprint])}
                onToast={onToast}
              />
            ) : <div className="triage-detail-empty"><ShieldCheck size={28} /><h3>Select a finding to investigate</h3><p>Use J/K to move through the queue and open correlated evidence.</p></div>}
          </div>
        ) : !error ? (
          <div className="daily-empty">
            <span><CircleCheck size={25} /></span>
            <h3>No findings need attention in this view</h3>
            <p>Change the scope or clear filters to review other findings.</p>
            <button
              className="button button-secondary"
              onClick={() => {
                setFilters(defaultFilters);
                setPage(1);
              }}
            >
              Clear filters
            </button>
          </div>
        ) : null}

        <footer className="daily-pagination">
          <p>
            Page <strong>{data?.page ?? page}</strong> of <strong>{data?.pageCount ?? 1}</strong>
          </p>
          <label>
            Rows
            <select
              value={pageSize}
              onChange={(event) => {
                setPageSize(Number(event.target.value));
                setPage(1);
              }}
            >
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
            </select>
          </label>
          <div>
            <button
              aria-label="Previous page"
              disabled={!data || data.page <= 1}
              onClick={() => setPage((value) => Math.max(1, value - 1))}
            >
              <ChevronLeft size={16} />
            </button>
            <button
              aria-label="Next page"
              disabled={!data || data.page >= data.pageCount}
              onClick={() => setPage((value) => value + 1)}
            >
              <ChevronRight size={16} />
            </button>
          </div>
        </footer>
      </section>

      {action ? (
        <TriageModal
          action={action}
          targetCount={actionTargets.length}
          defaultAssignee={
            activeFinding?.assignee && actionTargets.length === 1
              ? activeFinding.assignee
              : "Morgan Lee"
          }
          evidenceEligible={
            action === "follow-up" ||
            actionTargets.every((fingerprint) => {
              const finding = data?.items.find((item) => item.fingerprint === fingerprint);
              return Boolean(finding && decisionEligible(finding, data?.source));
            })
          }
          onClose={() => setAction(null)}
          onSaved={(savedUndo, warning) => {
            const reviewed = actionTargets.length;
            if (actionTargets.length === 1) moveActive(1);
            setAction(null);
            setSelected(new Set());
            setReviewedInSession((value) => value + reviewed);
            setUndo(savedUndo ? { ...savedUndo, count: reviewed } : null);
            setRefreshKey((value) => value + 1);
            onToast(
              warning || `${actionTargets.length} finding${actionTargets.length === 1 ? "" : "s"} updated.`,
            );
          }}
          fingerprints={actionTargets}
        />
      ) : null}

      {undo ? (
        <div className="undo-decision-toast" role="status">
          <CircleCheck size={17} />
          <p><strong>Decision saved</strong><span>You can revert it for five minutes.</span></p>
          <button onClick={() => void undoLastDecision()}><RotateCcw size={14} /> Undo</button>
          <button aria-label="Dismiss undo" onClick={() => setUndo(null)}><X size={14} /></button>
        </div>
      ) : null}

      {jiraOpen ? (
        <JiraTicketModal
          fingerprints={[...selected]}
          existingCount={data?.items.filter((item) => selected.has(item.fingerprint) && item.jiraIssueKey).length ?? 0}
          onClose={() => setJiraOpen(false)}
          onCreated={(created, existing) => {
            setJiraOpen(false);
            setSelected(new Set());
            setRefreshKey((value) => value + 1);
            onToast(`${created} Jira ticket${created === 1 ? "" : "s"} created${existing ? `; ${existing} already linked` : ""}.`);
          }}
        />
      ) : null}

      {saveViewOpen ? (
        <div className="modal-layer" role="dialog" aria-modal="true" aria-labelledby="save-view-title">
          <button className="modal-scrim" aria-label="Close save view" onClick={() => setSaveViewOpen(false)} />
          <div className="daily-compact-modal">
            <header>
              <div><p>Reusable scope</p><h2 id="save-view-title">Save current view</h2><span>Keep this combination of scope, filters, and sorting.</span></div>
              <button className="icon-button" aria-label="Close" onClick={() => setSaveViewOpen(false)}><X size={18} /></button>
            </header>
            <div className="daily-modal-body">
              <label className="form-field"><span>View name</span><input autoFocus value={viewName} onChange={(event) => setViewName(event.target.value)} maxLength={80} placeholder="Production internet exposure" /></label>
              <fieldset className="view-visibility"><legend>Visibility</legend><label><input type="radio" name="view-visibility" checked={viewVisibility === "personal"} onChange={() => setViewVisibility("personal")} /><span><strong>Personal</strong><small>Only you can use or change this view.</small></span></label><label><input type="radio" name="view-visibility" checked={viewVisibility === "team"} onChange={() => setViewVisibility("team")} /><span><strong>Security team</strong><small>Share this view with analysts and reviewers.</small></span></label></fieldset>
              <label className="daily-checkbox"><input type="checkbox" checked={viewDefault} onChange={(event) => setViewDefault(event.target.checked)} /><span><strong>Make this my default</strong><small>Open the inbox using this scope and filter set.</small></span></label>
            </div>
            <footer><button className="button button-secondary" onClick={() => setSaveViewOpen(false)}>Cancel</button><button className="button button-primary" disabled={viewName.trim().length < 3} onClick={() => void saveView()}><Save size={15} />Save view</button></footer>
          </div>
        </div>
      ) : null}

      {deleteViewOpen ? (
        <div className="modal-layer" role="dialog" aria-modal="true" aria-labelledby="delete-view-title">
          <button className="modal-scrim" aria-label="Cancel saved view deletion" onClick={() => setDeleteViewOpen(false)} />
          <div className="daily-compact-modal">
            <header>
              <div><p>Saved view</p><h2 id="delete-view-title">Delete this view?</h2><span>The underlying findings and review history will not be affected.</span></div>
              <button className="icon-button" aria-label="Close" onClick={() => setDeleteViewOpen(false)}><X size={18} /></button>
            </header>
            <footer><button className="button button-secondary" onClick={() => setDeleteViewOpen(false)}>Cancel</button><button className="button button-danger" onClick={() => void deleteView()}>Delete saved view</button></footer>
          </div>
        </div>
      ) : null}
    </>
  );
}

function FindingInvestigationPane({
  finding,
  source,
  position,
  total,
  onPrevious,
  onNext,
  onClose,
  onOpenGroup,
  onAction,
  onToast,
}: {
  finding: DailyFinding;
  source: InboxResponse["source"];
  position: number;
  total: number;
  onPrevious: () => void;
  onNext: () => void;
  onClose: () => void;
  onOpenGroup: () => void;
  onAction: (action: TriageAction) => void;
  onToast: (message: string) => void;
}) {
  const [tab, setTab] = useState<"evidence" | "history">("evidence");
  const [events, setEvents] = useState<FindingHistoryEvent[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  useEffect(() => {
    if (tab !== "history") return;
    const timer = window.setTimeout(() => {
      setHistoryLoading(true);
      fetch(`/api/findings?history=${encodeURIComponent(finding.fingerprint)}`)
        .then((response) => response.json())
        .then((payload: { events?: FindingHistoryEvent[] }) => setEvents(payload.events ?? []))
        .finally(() => setHistoryLoading(false));
    }, 0);
    return () => window.clearTimeout(timer);
  }, [finding.fingerprint, tab]);

  const eligible = decisionEligible(finding, source);
  const links = awsConsoleLinks(finding);

  async function copyValue(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    onToast(`${label} copied.`);
  }

  return (
      <aside className="finding-investigation-pane" aria-labelledby="finding-drawer-title">
        <header>
          <div>
            <p>Finding investigation</p>
            <h2 id="finding-drawer-title">{finding.title}</h2>
            <span>{finding.securityGroupName} · {finding.accountName} · {finding.region}</span>
          </div>
          <div className="pane-navigation"><span>{position} of {total}</span><button aria-label="Previous finding" disabled={position <= 1} onClick={onPrevious}><ChevronLeft size={16} /></button><button aria-label="Next finding" disabled={position >= total} onClick={onNext}><ChevronRight size={16} /></button><button className="icon-button" aria-label="Close investigation" onClick={onClose}><X size={18} /></button></div>
        </header>
        <div className="finding-drawer-summary">
          <span className={`drawer-risk-number risk-${riskTone(finding.riskScore)}`}>{finding.riskScore}<small>risk</small></span>
          <div>
            <span className={`severity-badge severity-${finding.severity}`}><span />{finding.severity}</span>
            <span className={`finding-status status-${finding.status}`}>{statusLabels[finding.status]}</span>
            <strong>{finding.verdict}</strong>
          </div>
        </div>
        <section className={`finding-evidence-mode evidence-${finding.evidence.state}`}>
          <ShieldCheck size={16} />
          <div>
            <strong>{finding.evidence.state.replaceAll("-", " ")} evidence · {finding.evidence.confidence}% confidence</strong>
            <span>{finding.evidence.sources.join(" · ")}</span>
            {finding.evidence.limitations.length ? <small>{finding.evidence.limitations.join(" ")}</small> : null}
          </div>
        </section>
        <div className="finding-drawer-actions">
          <button onClick={() => onAction("follow-up")}><CalendarClock size={15} />Follow up</button>
          <button disabled={!eligible} title={!eligible ? "Complete and refresh evidence before acknowledging." : "Keyboard shortcut: A"} onClick={() => onAction("acknowledged")}><CheckCheck size={15} />Acknowledge</button>
          <button disabled={!eligible} title={!eligible ? "Complete and refresh evidence before accepting risk." : "Keyboard shortcut: E"} onClick={() => onAction("accepted-risk")}><ShieldEllipsis size={15} />Accept risk</button>
          <button disabled={!eligible} title={!eligible ? "Complete and refresh evidence before resolving." : "Keyboard shortcut: R"} onClick={() => onAction("resolved")}><ShieldX size={15} />Resolve</button>
        </div>
        <div className="drawer-tabs" role="tablist">
          <button className={tab === "evidence" ? "active" : ""} role="tab" aria-selected={tab === "evidence"} onClick={() => setTab("evidence")}><ShieldCheck size={14} />Evidence</button>
          <button className={tab === "history" ? "active" : ""} role="tab" aria-selected={tab === "history"} onClick={() => setTab("history")}><History size={14} />Notes & history</button>
        </div>
        <div className="finding-drawer-body">
          {tab === "evidence" ? (
            <>
              <section className="finding-explanation">
                <AlertTriangle size={18} />
                <div><strong>Why this finding needs review</strong><p>{finding.title}. Gatewatch correlated the deployed rule, effective path, observed traffic, ownership, and change provenance before assigning this risk score.</p></div>
              </section>
              <section className="finding-detail-grid">
                <div><span>Organizational unit</span><strong>{finding.organizationalUnit}</strong><small>{finding.accountId}</small></div>
                <div><span>Application</span><strong>{finding.application}</strong><small>{finding.service}</small></div>
                <div><span>Owner</span><strong>{finding.owner}</strong><small>Assigned to {finding.assignee}</small></div>
                <div><span>Finding age</span><strong>{finding.ageDays === 0 ? "New today" : `${finding.ageDays} days`}</strong><small>First seen {formatDate(finding.firstSeenAt)}</small></div>
              </section>
              <section className="decision-summary-card">
                <header><div><span>Decision summary</span><h3>{finding.policyName}</h3><p>{finding.policyControl}</p></div><span className={`finding-status status-${finding.status}`}>{statusLabels[finding.status]}</span></header>
                <div className="decision-summary-grid"><div><span>Observed access</span><strong>{finding.ruleSummary}</strong></div><div><span>Approved intent</span><strong>{finding.approvedIntent}</strong><small>{finding.intentTicket || "No intent ticket linked"}</small></div></div>
                {finding.reasonCode ? <footer><strong>Last decision:</strong> {finding.reasonCode.replaceAll("-", " ")}{finding.nextReviewAt ? ` · Review ${formatDate(finding.nextReviewAt)}` : ""}{finding.approver ? ` · Approved by ${finding.approver}` : ""}</footer> : null}
              </section>
              <section className="risk-explanation-card">
                <header><div><h3>Why risk is {finding.riskScore}</h3><p>Transparent factor scoring from the latest evidence snapshot.</p></div><span>{finding.riskScore - finding.projectedRisk}<small>potential reduction</small></span></header>
                <div className="risk-factor-list">{finding.riskFactors.map((factor) => <article key={factor.key}><div><strong>{factor.label}</strong><span>+{factor.points}/{factor.maxPoints}</span></div><p>{factor.evidence}</p><span className="risk-factor-track"><i style={{ width: `${Math.min(100, factor.points / Math.max(1, factor.maxPoints) * 100)}%` }} /></span></article>)}</div>
                <footer><span>Current <strong>{finding.riskScore}</strong></span><ChevronRight size={14} /><span>Projected after recommendation <strong>{finding.projectedRisk}</strong></span></footer>
              </section>
              <section className="change-comparison-card">
                <header><div><h3>Exact configuration change</h3><p>{finding.changeEventId} · {finding.changeActor} · {finding.changeChannel}</p></div><span className={finding.changeApproved ? "approved" : "unapproved"}>{finding.changeApproved ? "Approved" : "Approval not found"}</span></header>
                <div><article><span>Before</span><code>{finding.changeBefore}</code></article><ChevronRight size={17} /><article><span>After</span><code>{finding.changeAfter}</code></article></div>
              </section>
              <section className="evidence-quick-actions" aria-label="Evidence links and copy actions">
                <a href={links.securityGroup} target="_blank" rel="noreferrer">AWS security group <ExternalLink size={12} /></a>
                <a href={links.config} target="_blank" rel="noreferrer">Config timeline <ExternalLink size={12} /></a>
                <a href={links.cloudTrail} target="_blank" rel="noreferrer">CloudTrail event <ExternalLink size={12} /></a>
                <button onClick={() => void copyValue("Security group ID", finding.securityGroupId)}><Clipboard size={12} /> SG ID</button>
                <button onClick={() => void copyValue("Account ID", finding.accountId)}><Clipboard size={12} /> Account</button>
                <button onClick={() => void copyValue("AWS CLI command", `aws ec2 describe-security-groups --region ${finding.region} --group-ids ${finding.securityGroupId}`)}><Clipboard size={12} /> AWS CLI</button>
              </section>
              <section className="finding-attachments">
                <div className="finding-attachments-heading">
                  <div>
                    <h3>Attached resources</h3>
                    <p>Workloads and managed-service interfaces using this security group</p>
                  </div>
                  <span>{finding.attachments.length}</span>
                </div>
                {finding.attachments.length ? (
                  <div className="finding-attachment-list">
                    {finding.attachments.map((attachment) => {
                      const tags = Object.entries(attachment.tags ?? {}).sort(([left], [right]) => left.localeCompare(right));
                      return (
                        <article key={`${attachment.type}:${attachment.id}:${attachment.networkInterfaceId ?? "direct"}`}>
                          <div className="finding-attachment-icon"><FolderTree size={17} /></div>
                          <div className="finding-attachment-content">
                            <header>
                              <div><strong>{attachment.name}</strong><small>{attachment.type} · {attachment.id}</small></div>
                              <em>{attachment.criticality}</em>
                            </header>
                            {attachment.description ? <p>{attachment.description}</p> : null}
                            <div className="finding-attachment-metadata">
                              {attachment.networkInterfaceId ? <span><b>Interface</b>{attachment.networkInterfaceId}</span> : null}
                              {attachment.privateAddress ? <span><b>Private IP</b>{attachment.privateAddress}</span> : null}
                              {attachment.publicAddress ? <span><b>Public IP</b>{attachment.publicAddress}</span> : null}
                            </div>
                            <div className="finding-attachment-tags" aria-label={`Tags for ${attachment.name}`}>
                              {tags.length ? tags.slice(0, 12).map(([key, value]) => <span key={key}><b>{key}</b>{value || "—"}</span>) : <small>No resource tags returned by AWS</small>}
                              {tags.length > 12 ? <small>+{tags.length - 12} more tags</small> : null}
                            </div>
                          </div>
                        </article>
                      );
                    })}
                  </div>
                ) : (
                  <div className="finding-attachments-empty">
                    <FolderTree size={20} />
                    <div><strong>No attached resources observed</strong><p>This security group is not associated with a network interface in the latest collection.</p></div>
                  </div>
                )}
              </section>
              <section className="finding-evidence-stack">
                <article><span><Network size={16} /></span><p><strong>Effective rule</strong><small>{finding.ruleSummary}</small></p></article>
                <article><span><ShieldAlert size={16} /></span><p><strong>Reachability</strong><small>{finding.pathSummary}</small></p></article>
                <article><span><ListChecks size={16} /></span><p><strong>Observed use</strong><small>{finding.trafficSummary}</small></p></article>
                <article><span><History size={16} /></span><p><strong>Change provenance</strong><small>{finding.changeSummary}</small></p></article>
              </section>
              <section className="finding-recommendation">
                <BadgeCheck size={17} />
                <div><strong>Recommended next step</strong><p>{finding.recommendation}</p></div>
              </section>
              {finding.jiraIssueKey && finding.jiraIssueUrl ? <a className="finding-jira-card" href={finding.jiraIssueUrl} target="_blank" rel="noreferrer"><TicketPlus size={17} /><div><strong>Tracked in Jira</strong><p>{finding.jiraIssueKey}{finding.jiraRemoteStatus ? ` · ${finding.jiraRemoteStatus}` : ""}{finding.jiraRemoteResolution ? ` · ${finding.jiraRemoteResolution}` : ""}</p>{finding.jiraLastSyncedAt ? <small>Synced {formatDate(finding.jiraLastSyncedAt)}</small> : null}</div><ExternalLink size={14} /></a> : null}
              {finding.note ? (
                <section className="finding-latest-note">
                  <NotebookPen size={16} />
                  <div><strong>Latest review note</strong><p>{finding.note}</p><small>{finding.reviewer} · {finding.updatedAt || "Recently"}{finding.ticketRef ? ` · ${finding.ticketRef}` : ""}</small></div>
                </section>
              ) : null}
              <button className="button button-secondary open-group-evidence" onClick={onOpenGroup}>Open complete security-group evidence <ChevronRight size={15} /></button>
            </>
          ) : (
            <section className="finding-history">
              <div className="history-heading"><div><h3>Decision history</h3><p>Append-only notes and workflow changes for this stable finding.</p></div><span>{events.length} events</span></div>
              {historyLoading ? <div className="history-loading"><RefreshCw className="spin" size={18} />Loading history…</div> : events.length ? (
                <div className="finding-timeline">
                  {events.map((event) => (
                    <article key={event.id}>
                      <span className="timeline-dot" />
                      <header><strong>{statusLabels[event.toStatus as FindingWorkflowStatus] ?? event.toStatus}</strong><time>{formatDate(event.createdAt)}</time></header>
                      <p>{event.note || "Workflow status updated."}</p>
                      <small>{event.actor} · Assigned to {event.assignee}{event.ticketRef ? ` · ${event.ticketRef}` : ""}</small>
                      {event.expiresAt ? <em><Clock3 size={12} />Expires {formatDate(event.expiresAt)}</em> : null}
                    </article>
                  ))}
                </div>
              ) : (
                <div className="history-empty"><NotebookPen size={22} /><strong>No review history yet</strong><p>Use Acknowledge, Follow up, or Accept risk to record the first decision.</p></div>
              )}
            </section>
          )}
        </div>
      </aside>
  );
}

function JiraTicketModal({
  fingerprints,
  existingCount,
  onClose,
  onCreated,
}: {
  fingerprints: string[];
  existingCount: number;
  onClose: () => void;
  onCreated: (created: number, existing: number) => void;
}) {
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function createTickets() {
    setSaving(true);
    setError("");
    try {
      const response = await fetch("/api/jira/issues", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ fingerprints }),
      });
      const payload = (await response.json()) as {
        created?: Array<{ key: string; url: string }>;
        existing?: Array<{ issueKey: string; issueUrl: string }>;
        failed?: Array<{ error: string }>;
        error?: string;
      };
      if (!response.ok) throw new Error(payload.error ?? payload.failed?.[0]?.error ?? "Jira tickets could not be created.");
      if (payload.failed?.length) {
        throw new Error(`${payload.created?.length ?? 0} tickets were created, but ${payload.failed.length} failed. Refresh findings before retrying.`);
      }
      onCreated(payload.created?.length ?? 0, payload.existing?.length ?? 0);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Jira tickets could not be created.");
    } finally {
      setSaving(false);
    }
  }

  return <div className="modal-layer" role="dialog" aria-modal="true" aria-labelledby="jira-ticket-title">
    <button className="modal-scrim" aria-label="Cancel Jira ticket creation" onClick={onClose} />
    <div className="daily-compact-modal jira-ticket-modal">
      <header><div><p>External remediation workflow</p><h2 id="jira-ticket-title">Create Jira tickets?</h2><span>{fingerprints.length} selected finding{fingerprints.length === 1 ? "" : "s"}</span></div><button className="icon-button" aria-label="Close" onClick={onClose}><X size={18} /></button></header>
      <div className="daily-modal-body">
        <div className="jira-ticket-guidance"><TicketPlus size={19} /><p><strong>One ticket per finding</strong><span>Each issue includes the security group, account, region, rule evidence, risk, owner, and recommended action.</span></p></div>
        {existingCount ? <div className="jira-existing-note"><CircleCheck size={15} />{existingCount} selected finding{existingCount === 1 ? " is" : "s are"} already linked and will not create duplicates.</div> : null}
        <p className="jira-ticket-boundary">Ticket creation is an external write to the Jira project configured by an administrator. Gatewatch records every created issue in its audit history.</p>
        {error ? <div className="form-error" role="alert"><CircleAlert size={15} />{error}</div> : null}
      </div>
      <footer><button className="button button-secondary" onClick={onClose}>Cancel</button><button className="button button-primary" disabled={saving} onClick={() => void createTickets()}>{saving ? <><RefreshCw className="spin" size={15} />Creating tickets…</> : <><TicketPlus size={15} />Create Jira tickets</>}</button></footer>
    </div>
  </div>;
}

function TriageModal({
  action,
  targetCount,
  defaultAssignee,
  fingerprints,
  evidenceEligible,
  onClose,
  onSaved,
}: {
  action: TriageAction;
  targetCount: number;
  defaultAssignee: string;
  fingerprints: string[];
  evidenceEligible: boolean;
  onClose: () => void;
  onSaved: (undo?: { token: string; expiresAt: string }, warning?: string) => void;
}) {
  const [assignee, setAssignee] = useState(defaultAssignee);
  const [note, setNote] = useState("");
  const [ticketRef, setTicketRef] = useState("");
  const [dueAt, setDueAt] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [controls, setControls] = useState("");
  const [reasonCode, setReasonCode] = useState("");
  const [nextReviewAt, setNextReviewAt] = useState("");
  const [resolutionEvidence, setResolutionEvidence] = useState("");
  const [createJira, setCreateJira] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const title =
    action === "follow-up"
      ? "Create follow-up"
      : action === "acknowledged"
        ? "Acknowledge finding"
        : action === "accepted-risk"
          ? "Accept risk"
          : "Resolve finding";
  const today = new Date().toISOString().slice(0, 10);
  const reasons = action === "follow-up"
    ? [["owner-validation", "Owner validation required"], ["remediation-planned", "Remediation planned"], ["evidence-gap", "Evidence gap"], ["suspected-drift", "Suspected configuration drift"]]
    : action === "acknowledged"
      ? [["approved-public-service", "Approved public service"], ["expected-internal-access", "Expected internal access"], ["compensating-control", "Protected by compensating control"], ["false-positive", "False positive"]]
      : action === "accepted-risk"
        ? [["temporary-business-requirement", "Temporary business requirement"], ["vendor-dependency", "Vendor dependency"], ["migration-window", "Migration window"], ["remediation-deferred", "Remediation deferred"]]
        : [["rule-removed", "Rule removed"], ["source-narrowed", "Source narrowed"], ["resource-decommissioned", "Resource decommissioned"], ["finding-invalidated", "Finding invalidated by evidence"]];

  async function submit() {
    setSaving(true);
    setError("");
    try {
      const response = await fetch("/api/findings", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          action: "triage",
          fingerprints,
          status: action,
          assignee,
          note,
          ticketRef,
          dueAt,
          expiresAt,
          reasonCode,
          nextReviewAt,
          resolutionEvidence,
          compensatingControls: controls
            .split("\n")
            .map((value) => value.trim())
            .filter(Boolean),
        }),
      });
      const payload = (await response.json()) as { updated?: number; undoToken?: string; undoExpiresAt?: string; error?: string };
      if (!response.ok || !payload.updated) {
        throw new Error(payload.error ?? "The findings could not be updated.");
      }
      let warning = "";
      if (createJira) {
        const jiraResponse = await fetch("/api/jira/issues", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ fingerprints }),
        });
        if (!jiraResponse.ok) warning = "The decision was saved, but Jira ticket creation needs attention.";
      }
      onSaved(
        payload.undoToken && payload.undoExpiresAt
          ? { token: payload.undoToken, expiresAt: payload.undoExpiresAt }
          : undefined,
        warning || undefined,
      );
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The findings could not be updated.");
    } finally {
      setSaving(false);
    }
  }

  const disabled =
    saving ||
    !reasonCode ||
    (action !== "follow-up" && !evidenceEligible) ||
    note.trim().length < (action === "follow-up" ? 6 : 12) ||
    (action === "follow-up" && (!assignee || !dueAt)) ||
    (action === "accepted-risk" &&
      (!ticketRef || !expiresAt || !controls.trim())) ||
    (action === "acknowledged" && !nextReviewAt) ||
    (action === "resolved" && resolutionEvidence.trim().length < 8);

  return (
    <div className="modal-layer" role="dialog" aria-modal="true" aria-labelledby="triage-modal-title">
      <button className="modal-scrim" aria-label="Close triage action" onClick={onClose} />
      <div className="daily-triage-modal">
        <header>
          <div>
            <p>{action === "accepted-risk" ? "Time-bound governance decision" : "Daily findings workflow"}</p>
            <h2 id="triage-modal-title">{title}</h2>
            <span>{targetCount} finding{targetCount === 1 ? "" : "s"} selected</span>
          </div>
          <button className="icon-button" aria-label="Close" onClick={onClose}><X size={18} /></button>
        </header>
        <div className="daily-modal-body">
          {action === "acknowledged" ? (
            <div className="triage-guidance"><CheckCheck size={17} /><p><strong>Acknowledgement keeps the finding active.</strong><span>Use this when the current exposure is understood but should continue to appear in monitoring.</span></p></div>
          ) : null}
          {action === "accepted-risk" ? (
            <div className="triage-guidance triage-warning"><ShieldEllipsis size={17} /><p><strong>Accepted risk is temporary and administrator-approved.</strong><span>It requires a linked ticket, compensating controls, and an expiration date.</span></p></div>
          ) : null}
          {action === "resolved" ? (
            <div className="triage-guidance"><ShieldX size={17} /><p><strong>Resolution closes the current observation.</strong><span>If the rule returns in a future snapshot, Gatewatch automatically reopens the finding.</span></p></div>
          ) : null}
          {!evidenceEligible && action !== "follow-up" ? <div className="form-error" role="alert"><CircleAlert size={15} />This decision is blocked until the evidence is complete, observed, and within freshness SLA. Create a follow-up instead.</div> : null}
          <label className="form-field"><span>Decision reason <em>Required</em></span><select value={reasonCode} onChange={(event) => setReasonCode(event.target.value)}><option value="">Choose a structured reason</option>{reasons.map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label>
          <div className="form-grid-two">
            <label className="form-field"><span>Assignee</span><div className="input-with-icon"><UserRound size={15} /><input list="finding-assignee-suggestions" value={assignee} onChange={(event) => setAssignee(event.target.value)} maxLength={120} placeholder="Analyst email or owning team" /><datalist id="finding-assignee-suggestions"><option value="Morgan Lee" /><option value="Payments Platform" /><option value="Cloud Operations" /><option value="Data Reliability" /><option value="Commerce Runtime" /><option value="Analytics Engineering" /></datalist></div></label>
            <label className="form-field"><span>Ticket {action === "accepted-risk" ? <em>Required</em> : <em>Optional</em>}</span><input value={ticketRef} onChange={(event) => setTicketRef(event.target.value)} maxLength={160} placeholder="SEC-1234" /></label>
          </div>
          {action === "follow-up" ? (
            <><label className="form-field"><span>Follow-up due <em>Required</em></span><input type="date" min={today} value={dueAt} onChange={(event) => setDueAt(event.target.value)} /></label><label className="daily-checkbox"><input type="checkbox" checked={createJira} onChange={(event) => setCreateJira(event.target.checked)} /><span><strong>Create a Jira ticket after saving</strong><small>Existing linked findings are automatically deduplicated.</small></span></label></>
          ) : null}
          {action === "acknowledged" ? <label className="form-field"><span>Review again <em>Required</em></span><input type="date" min={today} value={nextReviewAt} onChange={(event) => setNextReviewAt(event.target.value)} /></label> : null}
          {action === "accepted-risk" ? (
            <>
              <label className="form-field"><span>Exception expires <em>Required</em></span><input type="date" min={today} value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} /></label>
              <label className="form-field"><span>Compensating controls <em>One per line</em></span><textarea value={controls} onChange={(event) => setControls(event.target.value)} placeholder={"MFA required\nSession recording enabled\nDaily Flow Log review"} maxLength={2000} /></label>
            </>
          ) : null}
          {action === "resolved" ? <label className="form-field"><span>Remediation evidence <em>Required</em></span><textarea value={resolutionEvidence} onChange={(event) => setResolutionEvidence(event.target.value)} placeholder="Change request, Config snapshot, pull request, or validation command and result…" maxLength={2000} /></label> : null}
          <label className="form-field">
            <span>{action === "acknowledged" ? "Why this finding is acceptable" : action === "accepted-risk" ? "Business justification" : action === "resolved" ? "Resolution note" : "Follow-up note"} <em>Required</em></span>
            <textarea value={note} onChange={(event) => setNote(event.target.value)} maxLength={2000} placeholder={action === "acknowledged" ? "Explain the intended access, evidence reviewed, and why no immediate remediation is required…" : action === "resolved" ? "Summarize what changed and how the fix was verified…" : "Document context and the next action…"} />
            <small>{note.length}/2000</small>
          </label>
          <div className="snapshot-note"><FileCheck2 size={15} /><p><strong>Evidence snapshot and actor included</strong><span>The current rule, path, traffic, risk score, and authenticated reviewer are written to append-only history.</span></p></div>
          {error ? <div className="form-error" role="alert"><CircleAlert size={15} />{error}</div> : null}
        </div>
        <footer>
          <button className="button button-secondary" onClick={onClose}>Cancel</button>
          <button className="button button-primary" disabled={disabled} onClick={() => void submit()}>
            {saving ? <><RefreshCw size={15} className="spin" />Saving…</> : action === "follow-up" ? <><CalendarClock size={15} />Create follow-up</> : action === "acknowledged" ? <><CheckCheck size={15} />Save acknowledgement</> : action === "accepted-risk" ? <><ShieldEllipsis size={15} />Accept risk</> : <><ShieldX size={15} />Resolve finding</>}
          </button>
        </footer>
      </div>
    </div>
  );
}
