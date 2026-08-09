"use client";

import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  BellRing,
  BrainCircuit,
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
  Gauge,
  Globe2,
  History,
  ListChecks,
  Layers3,
  Network,
  NotebookPen,
  PackageCheck,
  Plus,
  RefreshCw,
  RotateCcw,
  Save,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldEllipsis,
  ShieldQuestion,
  ShieldX,
  Sparkles,
  SlidersHorizontal,
  TicketPlus,
  Target,
  ThumbsDown,
  ThumbsUp,
  UserRound,
  Users,
  Waypoints,
  Wrench,
  X,
} from "lucide-react";
import { csvDocument } from "../lib/csv";
import { useEffect, useMemo, useRef, useState } from "react";
import type {
  DailyFinding,
  FindingWorkflowStatus,
} from "../lib/daily-findings";
import type { AiAnalysisEnvelope, AiAnalysisMode } from "../lib/ai-security-analyst";
import {
  evidenceChecksForFinding,
  exposureTruthForFinding,
  groupSecurityGroupFindings,
  guidedSecurityGroupHunts,
  remediationPackageForFinding,
  translateNaturalLanguageHunt,
  type ExposureLane,
} from "../lib/security-group-triage";

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
  scope: string;
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
  items: Array<DailyFinding & { matchReasons: string[] }>;
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
  resultFacets: Record<"accounts" | "regions" | "severities" | "internet" | "owners" | "directions", Array<{ value: string; count: number }>>;
  resultGroupCount: number;
  exposureOverview: {
    groups: number;
    lanes: Record<ExposureLane, number>;
    matrix: Record<ExposureLane, Record<"critical" | "important" | "standard", number>>;
    hunts: Record<string, number>;
    outcomes: {
      criticalAssetsExposed: number;
      reopened: number;
      expiringExceptions: number;
      evidenceCompletePercent: number;
      exposureHours: number;
      potentialRiskReduction: number;
    };
  };
  evidenceMatches: Array<{
    fingerprint: string;
    sourceId: string;
    sourceType: string;
    evidenceClass: string;
    observedAt: string;
    accountId: string;
    region: string;
    resourceType: string;
    resourceId: string;
    eventName: string;
    disposition: string;
    matchReasons: string[];
  }>;
  searchScope: "findings" | "all";
  searchSuggestions: {
    fields: string[];
    values: Record<string, string[]>;
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
  queryDiagnostics: {
    unsupportedFields: string[];
    unclosedQuote: boolean;
    syntaxErrors: string[];
    complexityExceeded: boolean;
  };
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
  scope: "findings",
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
    scope: params.get("scope") ?? "findings",
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
      "Security group ARN",
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
      item.securityGroupArn,
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

async function requestAiAnalysis(mode: AiAnalysisMode, findings: DailyFinding[], question = "") {
  const response = await fetch("/api/ai/analysis", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ action: "analyze", mode, findings, question }),
  });
  const payload = await response.json() as { analysis?: AiAnalysisEnvelope; error?: string };
  if (!response.ok || !payload.analysis) throw new Error(payload.error ?? "AI analysis could not be completed.");
  return payload.analysis;
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
  const [builderOpen, setBuilderOpen] = useState(false);
  const [monitorOpen, setMonitorOpen] = useState(false);
  const [facetsOpen, setFacetsOpen] = useState(false);
  const [searchFocused, setSearchFocused] = useState(false);
  const [builderField, setBuilderField] = useState("account");
  const [builderOperator, setBuilderOperator] = useState("contains");
  const [builderValue, setBuilderValue] = useState("");
  const [builderConnector, setBuilderConnector] = useState<"AND" | "OR">("AND");
  const [builderNegated, setBuilderNegated] = useState(false);
  const [queueMode, setQueueMode] = useState<QueueMode>("security-groups");
  const [naturalLanguageOpen, setNaturalLanguageOpen] = useState(false);
  const [naturalLanguageInput, setNaturalLanguageInput] = useState("");
  const [aiOverview, setAiOverview] = useState<AiAnalysisEnvelope | null>(null);
  const [aiOverviewLoading, setAiOverviewLoading] = useState(false);
  const [aiOverviewError, setAiOverviewError] = useState("");
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

  const effectiveQuery = globalQuery || filters.q;
  const activeFragment = effectiveQuery.split(/\s+/).at(-1) ?? "";
  const searchSuggestions = useMemo(() => {
    if (!searchFocused || !activeFragment || !data) return [];
    const fieldMatch = activeFragment.match(/^([a-z][a-z0-9-]*):(.*)$/i);
    if (fieldMatch) {
      const field = fieldMatch[1].toLowerCase();
      const prefix = fieldMatch[2].replaceAll('"', "").toLowerCase();
      return (data.searchSuggestions.values[field] ?? [])
        .filter((value) => value.toLowerCase().includes(prefix))
        .slice(0, 7)
        .map((value) => {
          const safeValue = value.replaceAll('"', "");
          return { label: value, replacement: `${field}:${/\s/.test(safeValue) ? `"${safeValue}"` : safeValue}` };
        });
    }
    return data.searchSuggestions.fields
      .filter((field) => field.startsWith(activeFragment.toLowerCase()))
      .slice(0, 8)
      .map((field) => ({ label: `${field}:`, replacement: `${field}:` }));
  }, [activeFragment, data, searchFocused]);


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
    if (queueMode === "security-groups") params.set("group", "1");
    return params.toString();
  }, [filters, globalQuery, page, pageSize, queueMode]);

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

  function setDetailedQuery(value: string) {
    updateFilter("q", value);
    onGlobalQueryChange?.(value);
  }

  function applySearchSuggestion(replacement: string) {
    const start = effectiveQuery.slice(0, Math.max(0, effectiveQuery.length - activeFragment.length));
    setDetailedQuery(`${start}${replacement}`);
    setSearchFocused(false);
  }

  function addBuilderClause() {
    const value = builderValue.trim();
    if (!value) return;
    const numeric = ["risk", "confidence", "age", "recurrence", "flows", "coverage"].includes(builderField);
    const operator = numeric && builderOperator !== "contains" ? builderOperator : "";
    const encoded = /\s/.test(value) ? `"${value.replaceAll('"', "")}"` : value;
    const clause = `${builderNegated ? "NOT " : ""}${builderField}:${operator}${encoded}`;
    setDetailedQuery(effectiveQuery.trim() ? `${effectiveQuery.trim()} ${builderConnector} ${clause}` : clause);
    setBuilderValue("");
  }

  async function selectEveryResult() {
    if (!data || data.total > 100) {
      setError("Refine the search to 100 findings or fewer before selecting the complete result set.");
      return;
    }
    const params = new URLSearchParams(queryString);
    params.set("page", "1");
    params.set("pageSize", "100");
    const response = await fetch(`/api/findings?${params.toString()}`);
    const payload = (await response.json()) as InboxResponse & { error?: string };
    if (!response.ok) {
      setError(payload.error ?? "The full result set could not be selected.");
      return;
    }
    setPage(1);
    setPageSize(100);
    setData(payload);
    setSelected(new Set(payload.items.map((item) => item.fingerprint)));
    onToast(`${payload.total} search result${payload.total === 1 ? "" : "s"} selected.`);
  }

  async function exportEveryResult() {
    const params = new URLSearchParams(queryString);
    params.set("format", "csv");
    params.delete("page");
    params.delete("pageSize");
    const response = await fetch(`/api/findings?${params.toString()}`);
    if (!response.ok) {
      setError("The complete search export could not be prepared.");
      return;
    }
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement("a");
    link.href = url;
    link.download = "gatewatch-search-results.csv";
    link.click();
    URL.revokeObjectURL(url);
    onToast("Complete search results exported with query lineage.");
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

  const clusters = useMemo(() => groupSecurityGroupFindings(data?.items ?? []), [data?.items]);
  const naturalLanguagePreview = useMemo(
    () => translateNaturalLanguageHunt(naturalLanguageInput),
    [naturalLanguageInput],
  );

  function applyHunt(query: string, label: string) {
    setDetailedQuery(query);
    updateFilter("status", "open");
    setQueueMode("security-groups");
    onToast(`${label} hunt applied.`);
  }

  async function runAiHunt() {
    if (!data?.items[0] || !naturalLanguageInput.trim()) return;
    setAiOverviewLoading(true);
    setAiOverviewError("");
    try {
      const result = await requestAiAnalysis("hunt", [data.items[0]], naturalLanguageInput);
      setAiOverview(result);
      if (result.analysis.searchQuery) applyHunt(result.analysis.searchQuery, "AI-assisted");
      else setAiOverviewError("The request needs more detail before Gatewatch can create a safe query.");
    } catch (caught) {
      setAiOverviewError(caught instanceof Error ? caught.message : "AI search translation failed.");
    } finally {
      setAiOverviewLoading(false);
    }
  }

  async function runAiOverview(mode: "digest" | "cluster", findings: DailyFinding[] = data?.items ?? []) {
    if (!findings.length) return;
    setAiOverviewLoading(true);
    setAiOverviewError("");
    try {
      setAiOverview(await requestAiAnalysis(mode, findings.slice(0, 25)));
      onToast(mode === "digest" ? "AI daily digest prepared." : "AI cluster brief prepared.");
    } catch (caught) {
      setAiOverviewError(caught instanceof Error ? caught.message : "AI overview failed.");
    } finally {
      setAiOverviewLoading(false);
    }
  }

  function applyExposureSlice(lane: ExposureLane, criticality?: "critical" | "important" | "standard") {
    updateFilter("internet", lane === "confirmed" ? "internet" : lane === "unknown" ? "unknown" : "no-internet");
    const criticalityQuery = criticality === "critical"
      ? "criticality:Critical"
      : criticality === "important"
        ? "criticality:High"
        : criticality === "standard"
          ? "(criticality:Medium OR criticality:Low)"
          : "";
    setDetailedQuery(criticalityQuery);
    setQueueMode("security-groups");
  }

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
          <p className="eyebrow">AWS exposure operations</p>
          <h1>Security group exposure triage</h1>
          <p>
            Start with the groups that create a real path to important resources,
            understand the decisive evidence, and prepare a safe change package.
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

      <section className="fix-first-overview" aria-label="Fix first exposure lanes">
        <button className="exposure-lane lane-confirmed" onClick={() => applyExposureSlice("confirmed")}>
          <span><Globe2 size={18} /></span><p><strong>{data?.exposureOverview.lanes.confirmed ?? "—"}</strong><b>Confirmed internet</b><small>Public path proven end to end</small></p><ArrowRight size={16} />
        </button>
        <button className="exposure-lane lane-unknown" onClick={() => applyExposureSlice("unknown")}>
          <span><ShieldQuestion size={18} /></span><p><strong>{data?.exposureOverview.lanes.unknown ?? "—"}</strong><b>Evidence incomplete</b><small>Collect what is needed to decide</small></p><ArrowRight size={16} />
        </button>
        <button className="exposure-lane lane-internal" onClick={() => applyExposureSlice("internal")}>
          <span><Network size={18} /></span><p><strong>{data?.exposureOverview.lanes.internal ?? "—"}</strong><b>Internal risk</b><small>No public path; lateral access remains</small></p><ArrowRight size={16} />
        </button>
        <div className="exposure-coverage-card">
          <Gauge size={18} />
          <p><strong>{data?.exposureOverview.outcomes.evidenceCompletePercent ?? "—"}%</strong><b>decision-ready</b><small>{data?.coverage.accounts ?? 0} accounts · {data?.stats.staleAccounts ?? 0} stale</small></p>
        </div>
      </section>

      {clusters[0] ? <section className={`fix-first-card lane-${clusters[0].lane}`} aria-label="Highest priority security group">
        <div className="fix-first-rank"><Target size={18} /><span>Fix first</span><strong>{clusters[0].priorityScore}</strong></div>
        <div className="fix-first-content">
          <header><div><h2>{clusters[0].lead.securityGroupName}</h2><code>{clusters[0].lead.securityGroupArn}</code></div><span className={`exposure-verdict verdict-${clusters[0].lane}`}>{clusters[0].lane === "confirmed" ? "Internet confirmed" : clusters[0].lane === "unknown" ? "Evidence incomplete" : "Internal risk"}</span></header>
          <p>{clusters[0].reason}</p>
          <footer><span>{clusters[0].criticality} asset</span><span>{clusters[0].attachmentCount} resources</span><span>{clusters[0].findings.length} contributing signals</span><span>{clusters[0].lead.owner}</span></footer>
        </div>
        <button className="button button-primary" onClick={() => setActiveFinding(clusters[0].lead)}>Investigate <ArrowRight size={14} /></button>
      </section> : null}

      <section className="ai-overview-card" aria-label="Gatewatch AI analyst overview">
        <header><span><BrainCircuit size={19} /></span><div><p>Bedrock analyst</p><h2>{aiOverview ? aiOverview.analysis.title : "Summarize the current evidence-backed queue"}</h2></div><button className="button button-secondary" disabled={aiOverviewLoading || !data?.items.length} onClick={() => void runAiOverview("digest")}><Sparkles size={14} />{aiOverviewLoading ? "Analyzing…" : "Generate daily digest"}</button></header>
        {aiOverview ? <div className="ai-overview-content"><p>{aiOverview.analysis.executiveSummary}</p><div>{aiOverview.analysis.recommendedActions.slice(0, 3).map((action) => <span key={`${action.priority}:${action.action}`}><strong>{action.priority}</strong>{action.action}</span>)}</div><footer><span className={`ai-source ai-source-${aiOverview.source}`}>{aiOverview.source === "bedrock" ? "Amazon Bedrock" : "Deterministic fallback"}</span><span>{aiOverview.analysis.confidence}% confidence</span><span>{aiOverview.cacheHit ? "Cached" : `${aiOverview.usage.inputTokens + aiOverview.usage.outputTokens} tokens`}</span><button onClick={() => setAiOverview(null)}>Dismiss</button></footer></div> : <p>Gatewatch sends at most 25 compact, normalized findings—not raw logs—and keeps deterministic reachability and risk decisions authoritative.</p>}
        {aiOverviewError ? <div className="ai-inline-error" role="alert"><CircleAlert size={14} />{aiOverviewError}</div> : null}
      </section>

      <details className="scope-disclosure">
        <summary><FolderTree size={15} /> Organization scope <span>{filters.ou || filters.account || filters.region || "All monitored AWS accounts"}</span></summary>
        <section className="daily-scope-bar" aria-label="Organization scope">
          <div className="scope-organization"><FolderTree size={17} /><p><span>Organization</span><strong>{data?.items[0]?.organization ?? (data?.source.mode === "aws" ? "AWS account scope" : "Demonstration organization")}</strong></p></div>
          <label><span>Organizational unit</span><select value={filters.ou} onChange={(event) => updateFilter("ou", event.target.value)}><option value="">All organizational units</option>{data?.facets.organizationalUnits.map((value) => <option key={value}>{value}</option>)}</select></label>
          <label><span>AWS account</span><select value={filters.account} onChange={(event) => updateFilter("account", event.target.value)}><option value="">All accounts</option>{data?.facets.accounts.map((account) => <option value={account.id} key={account.id}>{account.name} · {account.id}</option>)}</select></label>
          <label><span>Region</span><select value={filters.region} onChange={(event) => updateFilter("region", event.target.value)}><option value="">All regions</option>{data?.facets.regions.map((value) => <option key={value}>{value}</option>)}</select></label>
          <div className="coverage-scope"><strong>{data?.coverage.accounts ?? "—"}</strong><span>accounts monitored</span>{data?.source ? <small>{data.source.mode === "aws" ? `${data.source.coveragePercent}% collected · ${data.source.freshnessMinutes}m old` : "Demonstration data"}</small> : null}</div>
        </section>
      </details>

      <section className="panel daily-inbox-panel">
        <section className="guided-hunts" aria-labelledby="guided-hunts-title">
          <header><div><Target size={17} /><p><strong id="guided-hunts-title">Security group hunts</strong><span>Start with a proven misconfiguration pattern, then refine the generated query.</span></p></div><button className="button button-secondary" onClick={() => setNaturalLanguageOpen((value) => !value)} aria-expanded={naturalLanguageOpen}><Sparkles size={14} />Describe a hunt</button></header>
          <div className="guided-hunt-scroll">
            {guidedSecurityGroupHunts.map((hunt) => <button key={hunt.id} onClick={() => applyHunt(hunt.query, hunt.title)}><span>{data?.exposureOverview.hunts[hunt.id] ?? 0}</span><strong>{hunt.title}</strong><small>{hunt.description}</small></button>)}
          </div>
          {naturalLanguageOpen ? <div className="natural-hunt-builder">
            <label><span>Describe the AWS security groups you want to find</span><textarea value={naturalLanguageInput} onChange={(event) => setNaturalLanguageInput(event.target.value)} maxLength={300} placeholder="Show production security groups with public database access, observed traffic, and no approval in the last 7 days." /></label>
            <div className={naturalLanguagePreview.recognized ? "recognized" : "unrecognized"}><span>Structured preview</span><code>{naturalLanguagePreview.query || "Add an environment, exposure, port, workflow state, account, or time window."}</code>{naturalLanguagePreview.explanations.length ? <small>{naturalLanguagePreview.explanations.join(" · ")}</small> : null}</div>
            <div className="natural-hunt-actions"><button className="button button-secondary" disabled={!naturalLanguagePreview.recognized} onClick={() => applyHunt(naturalLanguagePreview.query, "Described")}>Run transparent query <ArrowRight size={14} /></button><button className="button button-primary" disabled={!naturalLanguageInput.trim() || !data?.items.length || aiOverviewLoading} onClick={() => void runAiHunt()}><BrainCircuit size={14} />{aiOverviewLoading ? "Translating…" : "Ask Bedrock"}</button></div>
          </div> : null}
        </section>

        <details className="exposure-intelligence">
          <summary><Waypoints size={16} /><span><strong>Exposure intelligence</strong><small>Criticality matrix and outcome measures</small></span><ChevronsUpDown size={14} /></summary>
          <div className="exposure-intelligence-grid">
            <section className="exposure-matrix" aria-label="Exposure by asset criticality">
              <header><strong>Exposure × asset criticality</strong><span>Choose a cell to investigate that slice.</span></header>
              <div className="matrix-table">
                <span /> <b>Critical</b><b>Important</b><b>Standard</b>
                {(["confirmed", "unknown", "internal"] as const).map((lane) => <div className="matrix-row" key={lane}><strong>{lane === "confirmed" ? "Internet" : lane === "unknown" ? "Unknown" : "Internal"}</strong>{(["critical", "important", "standard"] as const).map((criticality) => <button className={`matrix-${lane}`} key={criticality} onClick={() => applyExposureSlice(lane, criticality)}><span>{data?.exposureOverview.matrix[lane][criticality] ?? 0}</span><small>groups</small></button>)}</div>)}
              </div>
            </section>
            <section className="outcome-metrics" aria-label="Security outcome metrics">
              <header><strong>Security outcomes</strong><span>Measures that should improve as exposure is removed.</span></header>
              <div>
                <article><Globe2 size={15} /><p><strong>{data?.exposureOverview.outcomes.criticalAssetsExposed ?? 0}</strong><span>Critical assets exposed</span></p></article>
                <article><Clock3 size={15} /><p><strong>{data?.exposureOverview.outcomes.exposureHours.toLocaleString() ?? 0}</strong><span>Open exposure hours</span></p></article>
                <article><History size={15} /><p><strong>{data?.exposureOverview.outcomes.reopened ?? 0}</strong><span>Reopened groups</span></p></article>
                <article><ShieldEllipsis size={15} /><p><strong>{data?.exposureOverview.outcomes.expiringExceptions ?? 0}</strong><span>Exceptions tracked</span></p></article>
                <article><FileCheck2 size={15} /><p><strong>{data?.exposureOverview.outcomes.evidenceCompletePercent ?? 0}%</strong><span>Decision-ready evidence</span></p></article>
                <article><Gauge size={15} /><p><strong>{data?.exposureOverview.outcomes.potentialRiskReduction ?? 0}</strong><span>Potential risk points removed</span></p></article>
              </div>
            </section>
          </div>
        </details>

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
          <button className="button button-secondary" onClick={() => setBuilderOpen((value) => !value)} aria-expanded={builderOpen}>
            <SlidersHorizontal size={14} /> Query builder
          </button>
          <button className="button button-secondary" disabled={!effectiveQuery.trim()} onClick={() => setMonitorOpen(true)}>
            <BellRing size={14} /> Monitor search
          </button>
          <button className="button button-secondary" disabled={!data?.total} onClick={() => void exportEveryResult()}>
            <Download size={14} /> Export all results
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
          <div className="daily-search-shell">
            <label className="daily-search">
              <Search size={16} />
              <input
                value={effectiveQuery}
                onChange={(event) => setDetailedQuery(event.target.value)}
                onFocus={() => setSearchFocused(true)}
                onBlur={() => window.setTimeout(() => setSearchFocused(false), 150)}
                placeholder="Search or use arn:, name:, account:, ingress:…"
                aria-label="Search daily findings"
                aria-describedby="daily-search-guidance"
                aria-autocomplete="list"
                maxLength={500}
              />
            </label>
            {searchSuggestions.length ? <div className="daily-search-suggestions" role="listbox" aria-label="Search suggestions">{searchSuggestions.map((suggestion) => <button type="button" role="option" aria-selected="false" key={suggestion.replacement} onMouseDown={(event) => event.preventDefault()} onClick={() => applySearchSuggestion(suggestion.replacement)}><Search size={12} /><span>{suggestion.label}</span><code>{suggestion.replacement}</code></button>)}</div> : null}
          </div>
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
            <FileCheck2 size={14} />
            <select value={filters.scope} onChange={(event) => updateFilter("scope", event.target.value)} aria-label="Search findings or all correlated AWS evidence">
              <option value="findings">Findings only</option>
              <option value="all">Findings + AWS evidence</option>
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
          <div className="daily-search-guidance" id="daily-search-guidance">
            <div>
              <strong>Detailed search</strong>
              <span>Combine clauses with spaces. Every clause must match.</span>
              <code>account:123456789012 ingress:&quot;TCP/443&quot; source:0.0.0.0/0</code>
            </div>
            <details>
              <summary>Search fields</summary>
              <p>
                <code>arn:</code> <code>sg:</code> <code>name:</code> <code>account:</code> <code>region:</code> <code>vpc:</code>
                <code>ingress:</code> <code>egress:</code> <code>rule:</code> <code>port:</code> <code>protocol:</code> <code>source:</code>
                <code>severity:</code> <code>risk:&gt;=70</code> <code>verdict:</code> <code>status:</code> <code>owner:</code> <code>assignee:</code>
                <code>app:</code> <code>env:</code> <code>ou:</code> <code>policy:</code> <code>path:</code> <code>resource:</code> <code>tag:</code>
                <code>actor:</code> <code>evidence:</code> <code>confidence:&gt;=70</code> <code>age:&gt;30</code>
                <code>intent:</code> <code>ticket:</code> <code>approved:false</code> <code>flows:&gt;0</code> <code>coverage:&gt;=90</code> <code>rule-id:</code> <code>criticality:</code>
              </p>
            </details>
            {data?.queryDiagnostics.unsupportedFields.length ? (
              <p className="daily-search-warning" role="alert">
                Unsupported search field{data.queryDiagnostics.unsupportedFields.length === 1 ? "" : "s"}: {data.queryDiagnostics.unsupportedFields.join(", ")}.
              </p>
            ) : data?.queryDiagnostics.unclosedQuote ? (
              <p className="daily-search-warning" role="alert">Close the quoted search phrase to run this query.</p>
            ) : data?.queryDiagnostics.syntaxErrors.length ? (
              <p className="daily-search-warning" role="alert">{data.queryDiagnostics.syntaxErrors[0]}</p>
            ) : null}
          </div>
          {builderOpen ? <div className="daily-query-builder" aria-label="Visual search query builder">
            <div><strong>Build a clause</strong><span>Choose a field and Gatewatch will generate valid syntax.</span></div>
            <label><span>Join</span><select value={builderConnector} onChange={(event) => setBuilderConnector(event.target.value as "AND" | "OR")}><option>AND</option><option>OR</option></select></label>
            <label><span>Field</span><select value={builderField} onChange={(event) => { setBuilderField(event.target.value); setBuilderOperator("contains"); }}><optgroup label="Identity"><option value="arn">ARN</option><option value="sg">Security group ID</option><option value="name">Security group name</option><option value="account">Cloud account</option><option value="region">Region</option><option value="vpc">VPC</option></optgroup><optgroup label="Rule"><option value="ingress">Ingress</option><option value="egress">Egress</option><option value="rule-id">Rule ID</option><option value="protocol">Protocol</option><option value="port">Port</option><option value="source">Source</option></optgroup><optgroup label="Risk and workflow"><option value="internet">Internet exposure</option><option value="criticality">Asset criticality</option><option value="severity">Severity</option><option value="risk">Risk</option><option value="status">Status</option><option value="owner">Owner</option><option value="assignee">Assignee</option><option value="recurrence">Recurrence</option></optgroup><optgroup label="Intent and evidence"><option value="intent">Approved intent</option><option value="ticket">Intent ticket</option><option value="approved">Change approval</option><option value="flows">Observed flows</option><option value="coverage">Flow Log coverage</option><option value="changed-after">Changed after</option><option value="changed-before">Changed before</option><option value="changed-by">Changed by</option><option value="evidence">Evidence</option><option value="confidence">Confidence</option><option value="resource">Attached resource</option><option value="tag">Resource tag</option></optgroup></select></label>
            <label><span>Operator</span><select value={builderOperator} disabled={!['risk', 'confidence', 'age', 'recurrence', 'flows', 'coverage'].includes(builderField)} onChange={(event) => setBuilderOperator(event.target.value)}><option value="contains">Contains / equals</option><option value=">=">At least</option><option value="<=">At most</option><option value=">">Greater than</option><option value="<">Less than</option></select></label>
            <label className="builder-value"><span>Value</span><input value={builderValue} onChange={(event) => setBuilderValue(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); addBuilderClause(); } }} list="query-builder-values" placeholder="Value or date" /><datalist id="query-builder-values">{(data?.searchSuggestions.values[builderField] ?? []).map((value) => <option value={value} key={value} />)}</datalist></label>
            <label className="builder-negate"><input type="checkbox" checked={builderNegated} onChange={(event) => setBuilderNegated(event.target.checked)} /> Exclude with NOT</label>
            <button type="button" className="button button-primary" disabled={!builderValue.trim()} onClick={addBuilderClause}><Plus size={14} />Add clause</button>
            {effectiveQuery ? <footer><span>Current expression</span><code>{effectiveQuery}</code><button type="button" onClick={() => setDetailedQuery("")}>Clear</button></footer> : null}
          </div> : null}
        </div>

        {data && effectiveQuery && !data.queryDiagnostics.syntaxErrors.length && !data.queryDiagnostics.unsupportedFields.length && !data.queryDiagnostics.unclosedQuote ? <section className="search-result-insights" aria-label="Search result facets">
          <header><div><strong>Result intelligence</strong><span>{data.total} findings across {data.resultGroupCount} security groups{data.evidenceMatches.length ? ` · ${data.evidenceMatches.length} matching evidence records shown` : ""}</span></div><button onClick={() => setFacetsOpen((value) => !value)} aria-expanded={facetsOpen}>{facetsOpen ? "Hide breakdown" : "Show breakdown"}</button></header>
          {facetsOpen ? <div>{Object.entries(data.resultFacets).map(([name, values]) => <section key={name}><strong>{name}</strong><div>{values.map((facet) => <button key={facet.value} onClick={() => {
            const field = name === "accounts" ? "account" : name === "regions" ? "region" : name === "severities" ? "severity" : name === "owners" ? "owner" : name === "directions" ? "rule" : "internet";
            const facetValue = (name === "accounts" ? facet.value.match(/\d{12}/)?.[0] ?? facet.value : facet.value).replaceAll('"', "");
            const clause = `${field}:${/\s/.test(facetValue) ? `"${facetValue}"` : facetValue}`;
            setDetailedQuery(effectiveQuery ? `${effectiveQuery} AND ${clause}` : clause);
          }}><span>{facet.value}</span><b>{facet.count}</b></button>)}</div></section>)}</div> : null}
        </section> : null}

        {selected.size ? (
          <div className="bulk-action-bar" role="toolbar" aria-label="Bulk findings actions">
            <strong>{selected.size} selected</strong>
            {data && selected.size === data.items.length && data.total > selected.size ? <button disabled={data.total > 100} title={data.total > 100 ? "Refine the search to 100 findings or fewer." : `Select all ${data.total} matching findings`} onClick={() => void selectEveryResult()}><CheckCheck size={14} />Select all {data.total} results</button> : null}
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
          <span><strong>{data?.total ?? 0}</strong> findings · <b>{data?.resultGroupCount ?? 0}</b> security groups · <b>{data?.stats.reviewedToday ?? 0}</b> reviewed today · <b>{reviewedInSession}</b> this session</span>
          <div className="queue-display-controls" aria-label="Queue display controls">
            <button className={queueMode === "findings" ? "active" : ""} onClick={() => { setQueueMode("findings"); setPage(1); }}><ListChecks size={13} /> Findings</button>
            <button className={queueMode === "security-groups" ? "active" : ""} onClick={() => { setQueueMode("security-groups"); setPage(1); }}><Layers3 size={13} /> Grouped</button>
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

        {data?.searchScope === "all" && effectiveQuery ? <section className="universal-evidence-results" aria-label="Matching AWS evidence">
          <header><div><FileCheck2 size={16} /><p><strong>Correlated AWS evidence</strong><span>Config, CloudTrail, Flow Logs, network analysis, service access, and managed findings searched with the same expression.</span></p></div><span>{data.evidenceMatches.length} shown</span></header>
          {data.evidenceMatches.length ? <div>{data.evidenceMatches.map((record) => <article key={record.fingerprint}><header><strong>{record.eventName || record.sourceType}</strong><span>{record.evidenceClass}</span></header><p>{record.resourceId || record.resourceType || "Unmatched resource"}</p><small>{record.accountId || "Unknown account"} · {record.region || "Unknown Region"} · {formatDate(record.observedAt)}</small>{record.matchReasons.length ? <footer>{record.matchReasons.map((reason) => <span key={reason}>{reason}</span>)}</footer> : null}</article>)}</div> : <div className="universal-evidence-empty">No normalized evidence records matched independently of the consolidated findings.</div>}
        </section> : null}

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
                      {effectiveQuery && item.matchReasons.length ? <div className="queue-match-reasons" aria-label="Why this finding matched">{item.matchReasons.map((reason) => <span key={reason}>{reason}</span>)}</div> : null}
                    </div>
                  </article>
                )) : clusters.map((cluster) => {
                  const lead = cluster.lead;
                  const allSelected = cluster.findings.every((item) => selected.has(item.fingerprint));
                  const truth = exposureTruthForFinding(lead);
                  return <article key={cluster.key} className={`triage-cluster exposure-cluster lane-${cluster.lane} ${activeFinding && cluster.findings.some((item) => item.fingerprint === activeFinding.fingerprint) ? "active" : ""}`}>
                    <header onClick={() => setActiveFinding(lead)}>
                      <label onClick={(event) => event.stopPropagation()}><input type="checkbox" checked={allSelected} aria-label={`Select all findings for ${lead.securityGroupName}`} onChange={(event) => setSelected((current) => {
                        const next = new Set(current);
                        cluster.findings.forEach((item) => event.target.checked ? next.add(item.fingerprint) : next.delete(item.fingerprint));
                        return next;
                      })} /></label>
                      <div className="cluster-identity"><strong>{lead.securityGroupName}</strong><code title={lead.securityGroupArn}>{lead.securityGroupArn}</code><small>{lead.accountName} · {lead.region} · {cluster.attachmentCount} resources · {cluster.criticality} criticality</small></div>
                      <span className={`exposure-verdict verdict-${cluster.lane}`}>{cluster.lane === "confirmed" ? "Internet confirmed" : cluster.lane === "unknown" ? "Evidence incomplete" : "Internal risk"}</span>
                      <span className={`compact-risk risk-${riskTone(cluster.maxRisk)}`} title={`Priority ${cluster.priorityScore}`}>{cluster.maxRisk}</span>
                    </header>
                    <p className="cluster-priority-reason">{cluster.reason}</p>
                    <div className="cluster-truth-strip" aria-label={`Exposure evidence for ${lead.securityGroupName}`}>{truth.map((step, index) => <div className={`truth-step truth-${step.state}`} key={step.key}><span>{step.label}</span><strong title={step.value}>{step.value}</strong>{index < truth.length - 1 ? <ArrowRight size={12} /> : null}</div>)}</div>
                    <div className="cluster-findings">{cluster.findings.map((item) => <button key={item.fingerprint} onClick={() => setActiveFinding(item)}><span className={`daily-severity severity-${item.severity}`} />{item.title}<ChevronRight size={13} /></button>)}</div>
                    <footer><span>{cluster.findings.length} contributing signal{cluster.findings.length === 1 ? "" : "s"} · {cluster.ruleCount} rule{cluster.ruleCount === 1 ? "" : "s"} · {cluster.recurrence} observation{cluster.recurrence === 1 ? "" : "s"}</span><div><button onClick={() => void runAiOverview("cluster", cluster.findings)}><BrainCircuit size={12} />AI cluster brief</button><button onClick={() => { const fingerprints = cluster.findings.map((item) => item.fingerprint); setSelected(new Set(fingerprints)); openAction("follow-up", fingerprints); }}>Follow up as group</button></div></footer>
                  </article>;
                })}
              </div>
            </section>
            {activeFinding ? (
              <FindingInvestigationPane
                key={activeFinding.fingerprint}
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
          selectionQuery={actionTargets.length > 1 ? effectiveQuery : ""}
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

      {monitorOpen ? <SearchMonitorModal
        query={effectiveQuery}
        filters={filters}
        resultCount={data?.total ?? 0}
        onClose={() => setMonitorOpen(false)}
        onSaved={() => {
          setMonitorOpen(false);
          onToast("Saved search monitor created. Future result-set transitions will be tracked.");
        }}
      /> : null}

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
  const [tab, setTab] = useState<"summary" | "ai" | "path" | "resources" | "remediation" | "history" | "raw">("summary");
  const [events, setEvents] = useState<FindingHistoryEvent[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [aiAnalysis, setAiAnalysis] = useState<AiAnalysisEnvelope | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState("");
  const [aiFeedback, setAiFeedback] = useState("");

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

  useEffect(() => {
    if (tab !== "ai" || aiAnalysis || aiLoading) return;
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      fetch(`/api/ai/analysis?fingerprint=${encodeURIComponent(finding.fingerprint)}&mode=finding`, { signal: controller.signal })
        .then((response) => response.json())
        .then((payload: { analysis?: AiAnalysisEnvelope | null }) => {
          if (payload.analysis) setAiAnalysis(payload.analysis);
        })
        .catch(() => undefined);
    }, 0);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [aiAnalysis, aiLoading, finding.fingerprint, tab]);

  const eligible = decisionEligible(finding, source);
  const links = awsConsoleLinks(finding);
  const exposureTruth = exposureTruthForFinding(finding);
  const evidenceChecks = evidenceChecksForFinding(finding);
  const remediation = remediationPackageForFinding(finding);
  const rawEvidence = useMemo(() => {
    try {
      return JSON.stringify(JSON.parse(finding.evidenceSnapshot), null, 2);
    } catch {
      return finding.evidenceSnapshot;
    }
  }, [finding.evidenceSnapshot]);

  async function copyValue(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    onToast(`${label} copied.`);
  }

  async function generateAiAnalysis() {
    setAiLoading(true);
    setAiError("");
    try {
      setAiAnalysis(await requestAiAnalysis("finding", [finding]));
      onToast("Evidence-cited AI analysis prepared.");
    } catch (caught) {
      setAiError(caught instanceof Error ? caught.message : "AI analysis could not be completed.");
    } finally {
      setAiLoading(false);
    }
  }

  async function submitAiFeedback(rating: "useful" | "incorrect" | "incomplete") {
    if (!aiAnalysis) return;
    const response = await fetch("/api/ai/analysis", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "feedback", analysisId: aiAnalysis.id, rating }) });
    if (!response.ok) { setAiError("AI feedback could not be saved."); return; }
    setAiFeedback(rating);
    onToast("AI feedback saved for evaluation.");
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
        <section className="drawer-exposure-truth" aria-label="Decisive exposure evidence">
          {exposureTruth.map((step, index) => <div className={`truth-step truth-${step.state}`} key={step.key}><span>{step.label}</span><strong>{step.value}</strong>{index < exposureTruth.length - 1 ? <ArrowRight size={13} /> : null}</div>)}
        </section>
        <div className="finding-drawer-actions">
          <button onClick={() => onAction("follow-up")}><CalendarClock size={15} />Follow up</button>
          <button disabled={!eligible} title={!eligible ? "Complete and refresh evidence before acknowledging." : "Keyboard shortcut: A"} onClick={() => onAction("acknowledged")}><CheckCheck size={15} />Acknowledge</button>
          <button disabled={!eligible} title={!eligible ? "Complete and refresh evidence before accepting risk." : "Keyboard shortcut: E"} onClick={() => onAction("accepted-risk")}><ShieldEllipsis size={15} />Accept risk</button>
          <button disabled={!eligible} title={!eligible ? "Complete and refresh evidence before resolving." : "Keyboard shortcut: R"} onClick={() => onAction("resolved")}><ShieldX size={15} />Resolve</button>
        </div>
        <div className="drawer-tabs" role="tablist">
          <button className={tab === "summary" ? "active" : ""} role="tab" aria-selected={tab === "summary"} onClick={() => setTab("summary")}><ShieldCheck size={14} />Summary</button>
          <button className={tab === "ai" ? "active" : ""} role="tab" aria-selected={tab === "ai"} onClick={() => setTab("ai")}><BrainCircuit size={14} />AI analysis</button>
          <button className={tab === "path" ? "active" : ""} role="tab" aria-selected={tab === "path"} onClick={() => setTab("path")}><Waypoints size={14} />Exposure path</button>
          <button className={tab === "resources" ? "active" : ""} role="tab" aria-selected={tab === "resources"} onClick={() => setTab("resources")}><FolderTree size={14} />Impact</button>
          <button className={tab === "remediation" ? "active" : ""} role="tab" aria-selected={tab === "remediation"} onClick={() => setTab("remediation")}><Wrench size={14} />Remediation</button>
          <button className={tab === "history" ? "active" : ""} role="tab" aria-selected={tab === "history"} onClick={() => setTab("history")}><History size={14} />Notes & history</button>
          <button className={tab === "raw" ? "active" : ""} role="tab" aria-selected={tab === "raw"} onClick={() => setTab("raw")}><FileCheck2 size={14} />Raw evidence</button>
        </div>
        <div className="finding-drawer-body">
          {tab === "ai" ? (
            <section className="ai-analysis-panel">
              <header className="drawer-section-heading"><div><p>Amazon Bedrock · advisory</p><h3>{aiAnalysis?.analysis.title ?? "Explain this finding from normalized evidence"}</h3></div>{aiAnalysis ? <span className={`ai-source ai-source-${aiAnalysis.source}`}>{aiAnalysis.source === "bedrock" ? "Bedrock" : "Deterministic fallback"}</span> : <BrainCircuit size={20} />}</header>
              <aside className="ai-authority-boundary"><ShieldCheck size={16} /><p><strong>Evidence remains authoritative</strong><span>AI cannot change the reachability verdict, risk score, workflow state, or AWS configuration. Every generated action requires analyst approval.</span></p></aside>
              {!aiAnalysis ? <div className="ai-first-run"><span><BrainCircuit size={25} /></span><h3>Generate an evidence-cited explanation</h3><p>Gatewatch sends a bounded normalized package for this security group. Raw uploaded logs, credentials, and unrelated account evidence are excluded.</p><button className="button button-primary" disabled={aiLoading} onClick={() => void generateAiAnalysis()}>{aiLoading ? <RefreshCw className="spin" size={14} /> : <Sparkles size={14} />}{aiLoading ? "Analyzing…" : "Analyze finding"}</button></div> : <>
                <div className="ai-analysis-hero"><div><span>Executive summary</span><p>{aiAnalysis.analysis.executiveSummary}</p></div><strong>{aiAnalysis.analysis.confidence}<small>confidence</small></strong></div>
                <section className="ai-why"><h3>Why it matters</h3><p>{aiAnalysis.analysis.whyItMatters}</p><small>{aiAnalysis.analysis.confidenceRationale}</small></section>
                <section className="ai-claims"><header><h3>Claims and evidence</h3><span>{aiAnalysis.analysis.claims.length}</span></header>{aiAnalysis.analysis.claims.length ? aiAnalysis.analysis.claims.map((claim, index) => <article key={`${claim.statement}:${index}`}><span className={`ai-basis basis-${claim.basis}`}>{claim.basis}</span><div><p>{claim.statement}</p><small>{claim.evidenceRefs.join(" · ")} · {claim.confidence}%</small></div></article>) : <p>No additional claims were produced.</p>}</section>
                <div className="ai-gap-grid"><section><h3>Contradictions</h3>{aiAnalysis.analysis.contradictions.length ? aiAnalysis.analysis.contradictions.map((item) => <p key={item}><ShieldQuestion size={13} />{item}</p>) : <p><Check size={13} />No contradiction identified.</p>}</section><section><h3>Evidence gaps</h3>{aiAnalysis.analysis.evidenceGaps.map((item) => <p key={item}><CircleAlert size={13} />{item}</p>)}</section></div>
                <section className="ai-actions"><h3>Reviewable actions</h3>{aiAnalysis.analysis.recommendedActions.map((action) => <article key={`${action.priority}:${action.action}`}><span>{action.priority}</span><div><strong>{action.action}</strong><p>{action.reason}</p></div><em>{action.requiresApproval ? "Approval required" : "Review"}</em></article>)}</section>
                <details className="ai-remediation-draft"><summary><Wrench size={14} /><span><strong>AI remediation draft</strong><small>Review-only CloudFormation and Terraform suggestions</small></span><ChevronRight size={13} /></summary><div><p>{aiAnalysis.analysis.remediation.summary}</p>{([["CloudFormation", aiAnalysis.analysis.remediation.cloudFormation], ["Terraform", aiAnalysis.analysis.remediation.terraform]] as const).map(([label, value]) => value ? <article key={label}><header><strong>{label}</strong><button onClick={() => void copyValue(`${label} AI draft`, value)}><Clipboard size={12} />Copy</button></header><pre><code>{value}</code></pre></article> : null)}<h4>Validation</h4>{aiAnalysis.analysis.remediation.validation.map((item, index) => <p key={item}><span>{index + 1}</span>{item}</p>)}<aside><RotateCcw size={13} />{aiAnalysis.analysis.remediation.rollback}</aside></div></details>
                <footer className="ai-provenance"><div><span>Model</span><strong>{aiAnalysis.modelId}</strong></div><div><span>Guardrail</span><strong>{aiAnalysis.guardrail.configured ? aiAnalysis.guardrail.action : "Application controls"}</strong></div><div><span>Usage</span><strong>{aiAnalysis.usage.inputTokens + aiAnalysis.usage.outputTokens} tokens · {aiAnalysis.usage.latencyMs} ms</strong></div><div><span>Cache</span><strong>{aiAnalysis.cacheHit ? "Reused" : "Fresh"}</strong></div></footer>
                <div className="ai-feedback"><span>Was this analysis useful?</span><button className={aiFeedback === "useful" ? "active" : ""} onClick={() => void submitAiFeedback("useful")}><ThumbsUp size={13} />Useful</button><button className={aiFeedback === "incorrect" ? "active" : ""} onClick={() => void submitAiFeedback("incorrect")}><ThumbsDown size={13} />Incorrect</button><button className={aiFeedback === "incomplete" ? "active" : ""} onClick={() => void submitAiFeedback("incomplete")}><CircleAlert size={13} />Incomplete</button></div>
              </>}
              {aiError ? <div className="ai-inline-error" role="alert"><CircleAlert size={14} />{aiError}</div> : null}
            </section>
          ) : tab === "summary" ? (
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
                <button onClick={() => void copyValue("Security group ARN", finding.securityGroupArn)}><Clipboard size={12} /> ARN</button>
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
          ) : tab === "path" ? (
            <section className="exposure-path-panel">
              <header className="drawer-section-heading">
                <div><p>Decisive evidence</p><h3>Is this security group actually reachable?</h3></div>
                <span className={`path-status path-${finding.pathStatus}`}>{finding.pathStatus}</span>
              </header>
              <div className="path-narrative">
                {exposureTruth.map((step, index) => (
                  <article className={`path-node path-node-${step.state}`} key={step.key}>
                    <span>{index + 1}</span>
                    <div><small>{step.label}</small><strong>{step.value}</strong></div>
                    {index < exposureTruth.length - 1 ? <ArrowRight size={16} /> : null}
                  </article>
                ))}
              </div>
              <div className="evidence-readiness-card">
                <header><div><h3>Evidence readiness</h3><p>Each decisive claim must be supported before a terminal decision is available.</p></div><strong>{evidenceChecks.filter((check) => check.state === "complete").length}/{evidenceChecks.length}</strong></header>
                <div className="evidence-check-list">
                  {evidenceChecks.map((check) => <article key={check.key} className={`evidence-check evidence-check-${check.state}`}><span>{check.state === "complete" ? <Check size={14} /> : check.state === "partial" ? <ShieldQuestion size={14} /> : <CircleAlert size={14} />}</span><div><strong>{check.label}</strong><small>{check.detail}</small></div><em>{check.state}</em></article>)}
                </div>
              </div>
              <aside className="traffic-caveat"><Gauge size={17} /><div><strong>Traffic is corroborating evidence, not proof of safety.</strong><p>No observed flows can mean the path was unused, the collection window was incomplete, or Flow Logs were unavailable. Reachability and routing evidence determine exposure.</p></div></aside>
            </section>
          ) : tab === "resources" ? (
            <section className="impact-panel">
              <header className="drawer-section-heading"><div><p>Blast radius</p><h3>{finding.attachments.length} attached resource{finding.attachments.length === 1 ? "" : "s"}</h3></div><span>{finding.application} · {finding.environment}</span></header>
              <div className="intent-impact-card">
                <div><span>Documented intent</span><strong>{finding.approvedIntent || "Owner intent not supplied"}</strong><small>{finding.intentTicket || "No linked approval ticket"}</small></div>
                <div><span>Intent status</span><strong>{finding.intentStatus.replaceAll("-", " ")}</strong><small>{finding.intentJustification || "No justification supplied"}</small></div>
              </div>
              {finding.attachments.length ? (
                <div className="finding-attachment-list">
                  {finding.attachments.map((attachment) => {
                    const tags = Object.entries(attachment.tags ?? {}).sort(([left], [right]) => left.localeCompare(right));
                    return <article key={`${attachment.type}:${attachment.id}:${attachment.networkInterfaceId ?? "direct"}`}>
                      <div className="finding-attachment-icon"><FolderTree size={17} /></div>
                      <div className="finding-attachment-content">
                        <header><div><strong>{attachment.name}</strong><small>{attachment.type} · {attachment.id}</small></div><em>{attachment.criticality}</em></header>
                        {attachment.description ? <p>{attachment.description}</p> : null}
                        <div className="finding-attachment-metadata">{attachment.networkInterfaceId ? <span><b>Interface</b>{attachment.networkInterfaceId}</span> : null}{attachment.privateAddress ? <span><b>Private IP</b>{attachment.privateAddress}</span> : null}{attachment.publicAddress ? <span><b>Public IP</b>{attachment.publicAddress}</span> : null}</div>
                        <div className="finding-attachment-tags" aria-label={`Tags for ${attachment.name}`}>{tags.length ? tags.slice(0, 12).map(([key, value]) => <span key={key}><b>{key}</b>{value || "—"}</span>) : <small>No resource tags returned by AWS</small>}{tags.length > 12 ? <small>+{tags.length - 12} more tags</small> : null}</div>
                      </div>
                    </article>;
                  })}
                </div>
              ) : <div className="finding-attachments-empty"><FolderTree size={20} /><div><strong>No attached resources observed</strong><p>This can indicate an unused group or incomplete attachment evidence. Confirm ENI and managed-service inventory before deletion.</p></div></div>}
            </section>
          ) : tab === "remediation" ? (
            <section className="remediation-panel">
              <header className="drawer-section-heading"><div><p>Safe change package</p><h3>{remediation.title}</h3></div><PackageCheck size={20} /></header>
              <div className="remediation-diff"><article><span>Current access</span><strong>{remediation.current}</strong></article><ArrowRight size={18} /><article><span>Proposed outcome</span><strong>{remediation.proposed}</strong></article></div>
              <div className="remediation-impact"><Target size={17} /><div><strong>Expected impact</strong><p>{remediation.impact}</p><small>{remediation.recommendation}</small></div></div>
              <div className="remediation-code-list">
                {([['AWS CLI', remediation.cli], ['CloudFormation guidance', remediation.cloudFormation], ['Terraform guidance', remediation.terraform]] as const).map(([label, value]) => <article key={label}><header><strong>{label}</strong><button onClick={() => void copyValue(label, value)}><Clipboard size={13} />Copy</button></header><pre><code>{value}</code></pre></article>)}
              </div>
              <div className="remediation-verification"><h3>Post-change verification</h3>{remediation.verification.map((step, index) => <div key={step}><span>{index + 1}</span><p>{step}</p></div>)}</div>
              <aside className="package-safety-note"><ShieldCheck size={16} /><p>Gatewatch produces an analyst-reviewed change package. It does not silently modify AWS resources.</p></aside>
            </section>
          ) : tab === "raw" ? (
            <section className="raw-evidence-panel">
              <header className="drawer-section-heading"><div><p>Source preservation</p><h3>Normalized evidence snapshot</h3></div><span>{finding.evidence.sources.length} sources</span></header>
              <div className="raw-evidence-meta"><div><span>Finding fingerprint</span><code>{finding.fingerprint}</code></div><div><span>Security group ARN</span><code>{finding.securityGroupArn}</code></div><div><span>Correlated observations</span><strong>{finding.observationCount}</strong></div><div><span>Last observed</span><strong>{formatDate(finding.lastObserved)}</strong></div></div>
              <pre className="raw-evidence-json"><code>{rawEvidence}</code></pre>
              <div className="raw-source-list"><strong>Correlated sources</strong>{finding.evidence.sources.map((item) => <span key={item}><FileCheck2 size={13} />{item}</span>)}</div>
              {finding.evidence.limitations.length ? <div className="raw-limitations"><CircleAlert size={15} /><div><strong>Known limitations</strong>{finding.evidence.limitations.map((item) => <p key={item}>{item}</p>)}</div></div> : null}
            </section>
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

function SearchMonitorModal({
  query,
  filters,
  resultCount,
  onClose,
  onSaved,
}: {
  query: string;
  filters: Filters;
  resultCount: number;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [schedule, setSchedule] = useState("daily");
  const [triggerMode, setTriggerMode] = useState("enters");
  const [destination, setDestination] = useState("notification-delivery");
  const [visibility, setVisibility] = useState<"personal" | "team">("personal");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function save() {
    setSaving(true);
    setError("");
    try {
      const response = await fetch("/api/organization-operations", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          action: "monitor-save",
          name,
          query,
          filters: { ...filters, surface: "daily-findings" },
          schedule,
          triggerMode,
          groupBy: "security-group",
          destinations: [destination],
          visibility,
        }),
      });
      const payload = (await response.json()) as { saved?: boolean; error?: string };
      if (!response.ok || !payload.saved) throw new Error(payload.error ?? "The search monitor could not be created.");
      onSaved();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The search monitor could not be created.");
    } finally {
      setSaving(false);
    }
  }

  return <div className="modal-layer" role="dialog" aria-modal="true" aria-labelledby="search-monitor-title">
    <button className="modal-scrim" aria-label="Cancel search monitor" onClick={onClose} />
    <div className="daily-compact-modal search-monitor-modal">
      <header><div><p>Continuous detection</p><h2 id="search-monitor-title">Monitor this search</h2><span>Track when findings enter or leave this {resultCount}-result population.</span></div><button className="icon-button" aria-label="Close" onClick={onClose}><X size={18} /></button></header>
      <div className="daily-modal-body">
        <label className="form-field"><span>Monitor name <em>Required</em></span><input autoFocus value={name} onChange={(event) => setName(event.target.value)} maxLength={120} placeholder="New production admin exposure" /></label>
        <div className="monitor-query-preview"><strong>Evaluated query</strong><code>{query}</code><small>Current scope and filters are stored with the query and re-evaluated server-side.</small></div>
        <div className="form-grid-two"><label className="form-field"><span>Schedule</span><select value={schedule} onChange={(event) => setSchedule(event.target.value)}><option value="hourly">Hourly</option><option value="daily">Daily</option><option value="weekly">Weekly</option></select></label><label className="form-field"><span>Notify when</span><select value={triggerMode} onChange={(event) => setTriggerMode(event.target.value)}><option value="enters">A finding enters</option><option value="leaves">A finding leaves</option><option value="severity-change">Severity changes</option><option value="recurrence">Exposure recurs</option><option value="coverage-gap">Evidence coverage degrades</option></select></label></div>
        <label className="form-field"><span>Destination</span><select value={destination} onChange={(event) => setDestination(event.target.value)}><option value="notification-delivery">Configured email/webhook policy</option><option value="jira">Jira remediation queue</option><option value="security-hub">AWS Security Hub custom action</option></select></label>
        <fieldset className="view-visibility"><legend>Visibility</legend><label><input type="radio" name="monitor-visibility" checked={visibility === "personal"} onChange={() => setVisibility("personal")} /><span><strong>Personal</strong><small>Only you and administrators can manage it.</small></span></label><label><input type="radio" name="monitor-visibility" checked={visibility === "team"} onChange={() => setVisibility("team")} /><span><strong>Security team</strong><small>Analysts can see and run the monitor.</small></span></label></fieldset>
        {error ? <div className="form-error" role="alert"><CircleAlert size={15} />{error}</div> : null}
      </div>
      <footer><button className="button button-secondary" onClick={onClose}>Cancel</button><button className="button button-primary" disabled={saving || name.trim().length < 3} onClick={() => void save()}>{saving ? <><RefreshCw className="spin" size={14} />Saving…</> : <><BellRing size={14} />Create monitor</>}</button></footer>
    </div>
  </div>;
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
  selectionQuery,
  evidenceEligible,
  onClose,
  onSaved,
}: {
  action: TriageAction;
  targetCount: number;
  defaultAssignee: string;
  fingerprints: string[];
  selectionQuery: string;
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
          {targetCount > 1 ? <div className="bulk-audit-preview"><ListChecks size={17} /><div><strong>Guarded bulk operation</strong><p>{targetCount} stable finding fingerprints will be revalidated by the API. Gatewatch writes one event per finding plus a bulk audit summary and provides a five-minute undo.</p>{selectionQuery ? <code>{selectionQuery}</code> : null}</div></div> : null}
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
