"use client";

import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  Ban,
  BookOpenCheck,
  Boxes,
  BriefcaseBusiness,
  Check,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Clock3,
  Code2,
  Crown,
  Download,
  Eye,
  FileCode2,
  FileCheck2,
  FileWarning,
  Filter,
  GitPullRequest,
  Globe2,
  ListChecks,
  Network,
  Plus,
  Radio,
  RefreshCw,
  Route,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldEllipsis,
  Sparkles,
  Target,
  TrendingDown,
  Trash2,
  TriangleAlert,
  UserRoundCheck,
  Users,
  UploadCloud,
  WandSparkles,
  X,
  Zap,
} from "lucide-react";
import { csvDocument } from "../lib/csv";
import type { LucideIcon } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import type { LiveIntelligence } from "../lib/live-intelligence";
import {
  consolidateInfrastructureReviews,
  MAX_IAC_BATCH_RULES,
  MAX_IAC_FILE_BYTES,
  MAX_IAC_FILES,
  reviewInfrastructureFile,
  type IacFileReview,
  type IacSecurityGroupReview,
  type IacSeverity,
} from "../lib/iac-security-review";
import {
  controlMappings,
  driftEvents,
  exceptionSeeds,
  exposureRecords,
  hygieneIssues,
  iacChanges,
  ownerQueues,
  programTrend,
  ruleRecommendations,
  type ExceptionSeed,
  type ExposureRecord,
} from "../lib/product-intelligence-data";

const demonstrationIntelligence: LiveIntelligence = {
  mode: "demonstration",
  source: null,
  exposureRecords,
  ruleRecommendations,
  driftEvents,
  ownerQueues,
  controlMappings,
  hygieneIssues,
  iacChanges,
  programTrend,
};

type WorkflowRecord = {
  id: string;
  kind: string;
  subjectId: string;
  status: string;
  owner: string;
  note: string;
  ticketRef: string;
  expiresAt: string;
  payload: Record<string, unknown>;
  updatedAt?: string;
};

type ToastHandler = (message: string) => void;

function useIntelligenceData() {
  const [data, setData] = useState<LiveIntelligence>(demonstrationIntelligence);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    fetch("/api/intelligence/data", { cache: "no-store" })
      .then(async (response) => {
        const payload = (await response.json()) as {
          intelligence?: LiveIntelligence;
          error?: string;
        };
        if (!response.ok || !payload.intelligence) {
          throw new Error(payload.error ?? "Live intelligence is unavailable.");
        }
        return payload.intelligence;
      })
      .then((intelligence) => {
        if (active) setData(intelligence);
      })
      .catch((caught) => {
        if (active) {
          setError(
            caught instanceof Error
              ? caught.message
              : "Live intelligence is unavailable.",
          );
        }
      });
    return () => {
      active = false;
    };
  }, []);
  return { data, error };
}

function EvidenceMode({ data }: { data: LiveIntelligence }) {
  return (
    <span className={`read-only-pill evidence-mode-${data.mode}`}>
      {data.mode === "live" ? <CircleCheck size={14} /> : <TriangleAlert size={14} />}
      {data.mode === "live"
        ? `Live AWS evidence · ${data.source?.coveragePercent ?? 0}% coverage`
        : "Demonstration intelligence · connect AWS evidence"}
    </span>
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

function useWorkflows(onToast: ToastHandler) {
  const [records, setRecords] = useState<Record<string, WorkflowRecord>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    fetch("/api/intelligence")
      .then(async (response) => {
        const payload = (await response.json()) as {
          records?: WorkflowRecord[];
          error?: string;
        };
        if (!response.ok) throw new Error(payload.error ?? "Workflow data is unavailable.");
        return payload;
      })
      .then((payload) => {
        if (!active) return;
        setRecords(
          Object.fromEntries((payload.records ?? []).map((record) => [record.id, record])),
        );
      })
      .catch((caught) => {
        if (active) setError(caught instanceof Error ? caught.message : "Workflow data is unavailable.");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  async function save(input: Omit<WorkflowRecord, "updatedAt">) {
    setError("");
    try {
      const response = await fetch("/api/intelligence", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "upsert", ...input }),
      });
      const payload = (await response.json()) as {
        record?: WorkflowRecord;
        error?: string;
      };
      if (!response.ok || !payload.record) {
        const message = payload.error ?? "The workflow could not be saved.";
        setError(message);
        return null;
      }
      setRecords((current) => ({ ...current, [payload.record!.id]: payload.record! }));
      return payload.record;
    } catch (caught) {
      const message =
        caught instanceof Error ? caught.message : "The workflow could not be saved.";
      setError(message);
      return null;
    }
  }

  async function remove(id: string) {
    try {
      const response = await fetch("/api/intelligence", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action: "delete", id }),
      });
      const payload = (await response.json()) as { deleted?: boolean; error?: string };
      if (!response.ok || !payload.deleted) {
        const message = payload.error ?? "The record could not be deleted.";
        setError(message);
        return false;
      }
      setRecords((current) => {
        const next = { ...current };
        delete next[id];
        return next;
      });
      onToast("Draft exception deleted.");
      return true;
    } catch (caught) {
      const message =
        caught instanceof Error ? caught.message : "The record could not be deleted.";
      setError(message);
      return false;
    }
  }

  return { records, loading, error, save, remove };
}

function WorkflowError({ message }: { message: string }) {
  return message ? (
    <div className="intel-error" role="alert">
      <CircleAlert size={16} /> {message}
    </div>
  ) : null;
}

function downloadCsv(filename: string, rows: string[][]) {
  const content = csvDocument(rows);
  const url = URL.createObjectURL(new Blob([content], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function verdictClass(verdict: string) {
  if (verdict === "Confirmed public service") return "confirmed";
  if (verdict === "Internet path exists") return "reachable";
  if (verdict === "Internal only") return "internal";
  if (verdict === "Broad but unreachable") return "unreachable";
  return "incomplete";
}

export function ExposureIntelligenceView({
  onToast,
}: {
  onToast: ToastHandler;
}) {
  const intelligence = useIntelligenceData();
  const records = intelligence.data.exposureRecords;
  const [query, setQuery] = useState("");
  const [verdict, setVerdict] = useState("all");
  const [selectedId, setSelectedId] = useState("");
  const [mode, setMode] = useState<"exposure" | "paths">("exposure");
  const selected = records.find((record) => record.id === selectedId) ?? records[0] ?? null;
  const filtered = records.filter((record) => {
    const text = [
      record.groupName,
      record.groupId,
      record.application,
      record.owner,
      record.account,
      record.verdict,
      record.toxicSignals.join(" "),
    ]
      .join(" ")
      .toLowerCase();
    return (
      (verdict === "all" || record.verdict === verdict) &&
      (!query || text.includes(query.toLowerCase()))
    );
  });
  const confirmed = records.filter(
    (record) => record.verdict === "Confirmed public service",
  ).length;
  const toxic = records.filter((record) => record.toxicSignals.length >= 3).length;

  return (
    <>
      <PageHeader
        eyebrow="Effective exposure"
        title="Exposure intelligence"
        description="Separate broad configuration from a real network path, an observed public service, and a harmful combination of risks."
        actions={
          <>
            <EvidenceMode data={intelligence.data} />
            <div className="segmented-control" aria-label="Exposure view">
              <button className={mode === "exposure" ? "active" : ""} onClick={() => setMode("exposure")}>
                <ShieldAlert size={14} /> Verdicts
              </button>
              <button className={mode === "paths" ? "active" : ""} onClick={() => setMode("paths")}>
                <Route size={14} /> Attack paths
              </button>
            </div>
            <button
              className="button button-secondary"
              onClick={() => {
                downloadCsv("gatewatch-effective-exposure.csv", [
                  ["Security group", "Verdict", "Confidence", "Risk", "Owner", "Ports", "Public address"],
                  ...filtered.map((record) => [
                    record.groupName,
                    record.verdict,
                    `${record.confidence}%`,
                    String(record.riskScore),
                    record.owner,
                    record.ports,
                    record.publicAddress,
                  ]),
                ]);
                onToast(`Exported ${filtered.length} exposure verdicts.`);
              }}
            >
              <Download size={15} /> Export
            </button>
          </>
        }
      />

      <section className="intel-metric-strip">
        <article><span className="metric-red"><Globe2 size={17} /></span><p>Confirmed public<strong>{confirmed}</strong><small>Service externally observed</small></p></article>
        <article><span className="metric-amber"><Route size={17} /></span><p>Internet paths<strong>{records.filter((record) => record.verdict === "Internet path exists").length}</strong><small>Configured network paths</small></p></article>
        <article><span className="metric-violet"><Zap size={17} /></span><p>Toxic combinations<strong>{toxic}</strong><small>Three or more risk signals</small></p></article>
        <article><span className="metric-green"><TrendingDown size={17} /></span><p>Broad but unreachable<strong>{records.filter((record) => record.verdict === "Broad but unreachable").length}</strong><small>Deprioritized with evidence</small></p></article>
      </section>

      {mode === "exposure" ? (
        <div className="exposure-layout">
          <section className="panel exposure-index">
            <div className="intel-toolbar">
              <label className="table-search">
                <Search size={15} />
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search exposure, owner, or application…" />
              </label>
              <label className="filter-select">
                <Filter size={14} />
                <select value={verdict} onChange={(event) => setVerdict(event.target.value)} aria-label="Filter by exposure verdict">
                  <option value="all">All verdicts</option>
                  <option>Confirmed public service</option>
                  <option>Internet path exists</option>
                  <option>Internal only</option>
                  <option>Broad but unreachable</option>
                  <option>Evidence incomplete</option>
                </select>
              </label>
            </div>
            <div className="exposure-list">
              {filtered.map((record) => (
                <button
                  className={selected?.id === record.id ? "active" : ""}
                  onClick={() => setSelectedId(record.id)}
                  key={record.id}
                >
                  <span className={`verdict-icon verdict-${verdictClass(record.verdict)}`}>
                    {record.verdict === "Confirmed public service" ? <Radio size={16} /> : record.verdict === "Broad but unreachable" ? <Ban size={16} /> : <Route size={16} />}
                  </span>
                  <p>
                    <strong>{record.groupName}</strong>
                    <span>{record.application} · {record.owner}</span>
                    <small>{record.account} · {record.region}</small>
                  </p>
                  <span className={`verdict-chip verdict-${verdictClass(record.verdict)}`}>{record.verdict}</span>
                  <em>{record.riskScore}</em>
                </button>
              ))}
            </div>
          </section>
          {selected ? (
            <ExposureDetail record={selected} onToast={onToast} />
          ) : (
            <section className="panel intel-empty">
              <ShieldCheck size={24} />
              <h2>No broad exposure was observed</h2>
              <p>The current AWS snapshot contains no security groups with internet-wide rules.</p>
            </section>
          )}
        </div>
      ) : (
        <AttackPathBoard records={records} onSelect={(record) => { setSelectedId(record.id); setMode("exposure"); }} />
      )}
    </>
  );
}

function ExposureDetail({
  record,
  onToast,
}: {
  record: ExposureRecord;
  onToast: ToastHandler;
}) {
  return (
    <aside className="panel exposure-detail">
      <div className="exposure-detail-hero">
        <div>
          <span className={`verdict-chip verdict-${verdictClass(record.verdict)}`}>{record.verdict}</span>
          <h2>{record.groupName}</h2>
          <p>{record.groupId} · {record.environment} · {record.region}</p>
        </div>
        <div className="confidence-score"><strong>{record.confidence}%</strong><span>confidence</span></div>
      </div>
      <div className="exposure-proof-grid">
        <div><span>Broad configuration</span><strong>{record.ports}</strong><small>AWS Config confirmed</small></div>
        <div><span>Public address</span><strong>{record.publicAddress}</strong><small>Resource relationship graph</small></div>
        <div><span>Route verdict</span><strong>{record.routeEvidence}</strong><small>Static path analysis</small></div>
        <div><span>External observation</span><strong>{record.externalEvidence}</strong><small>Last observed {record.lastObserved}</small></div>
      </div>
      <section className="toxic-combination">
        <div><Zap size={17} /><p><strong>Harmful combination</strong><span>{record.toxicSignals.length} connected signals increase likely impact</span></p></div>
        <div className="toxic-signals">
          {record.toxicSignals.map((signal, index) => (
            <span key={signal}><i>{index + 1}</i>{signal}</span>
          ))}
        </div>
        <dl>
          <div><dt>Data context</dt><dd>{record.dataClass}</dd></div>
          <div><dt>Identity context</dt><dd>{record.privilegedIdentity}</dd></div>
          <div><dt>Critical vulnerabilities</dt><dd>{record.criticalVulnerabilities}</dd></div>
        </dl>
      </section>
      <section className="path-evidence">
        <h3>Effective path</h3>
        <div>
          {record.path.map((hop, index) => (
            <span key={`${hop}-${index}`}>{hop}{index < record.path.length - 1 ? <ChevronRight size={12} /> : null}</span>
          ))}
        </div>
      </section>
      <div className="detail-actions">
        <button className="button button-primary" onClick={() => onToast(`${record.groupName} added to the priority review queue.`)}>
          <FileCheck2 size={15} /> Prioritize review
        </button>
        <button className="button button-secondary" onClick={() => onToast("Evidence package prepared with path, scan, identity, and data context.")}>
          <Download size={15} /> Evidence
        </button>
      </div>
    </aside>
  );
}

function AttackPathBoard({
  records,
  onSelect,
}: {
  records: ExposureRecord[];
  onSelect: (record: ExposureRecord) => void;
}) {
  return (
    <div className="attack-path-board">
      {records.filter((record) => record.toxicSignals.length >= 3).map((record, rank) => (
        <article className="panel attack-path-card" key={record.id}>
          <header>
            <span>#{rank + 1}</span>
            <div><h2>{record.application}</h2><p>{record.groupName} · Risk {record.riskScore}</p></div>
            <span className={`verdict-chip verdict-${verdictClass(record.verdict)}`}>{record.verdict}</span>
          </header>
          <div className="attack-path-flow">
            {record.path.map((hop, index) => (
              <div key={`${record.id}-${hop}`}><span>{index === 0 ? <Globe2 size={15} /> : index === record.path.length - 1 ? <Crown size={15} /> : <Network size={15} />}</span><strong>{hop}</strong>{index < record.path.length - 1 ? <ArrowRight size={14} /> : null}</div>
            ))}
          </div>
          <div className="attack-path-signals">
            {record.toxicSignals.map((signal) => <span key={signal}><AlertTriangle size={12} />{signal}</span>)}
          </div>
          <footer><p><strong>Best choke point</strong><span>Replace the broad rule on {record.groupName}; {Math.max(1, record.path.length * 3)} paths removed.</span></p><button className="button button-secondary" onClick={() => onSelect(record)}>Investigate <ChevronRight size={14} /></button></footer>
        </article>
      ))}
    </div>
  );
}

export function RecommendationCenterView({
  onToast,
}: {
  onToast: ToastHandler;
}) {
  const workflow = useWorkflows(onToast);
  const intelligence = useIntelligenceData();
  const recommendations = intelligence.data.ruleRecommendations;
  const [tab, setTab] = useState<"advisor" | "hygiene" | "iac">("advisor");
  const [selectedId, setSelectedId] = useState(recommendations[0]?.id ?? "");
  const [simulated, setSimulated] = useState(false);
  const [busy, setBusy] = useState("");
  const selected =
    recommendations.find((item) => item.id === selectedId) ?? recommendations[0] ?? null;

  async function updateRecommendation(status: string) {
    if (!selected) return;
    setBusy(selected.id);
    try {
      const saved = await workflow.save({
        id: selected.id,
        kind: "recommendation",
        subjectId: selected.groupId,
        status,
        owner: selected.owner,
        note: `Least-privilege recommendation for ${selected.currentRule}`,
        ticketRef: status === "approved" ? `SEC-${2400 + recommendations.indexOf(selected)}` : "",
        expiresAt: "",
        payload: { proposedRules: selected.proposedRules, riskAfter: selected.riskAfter },
      });
      if (!saved) return;
      onToast(`${selected.groupName} recommendation is now ${status}.`);
    } finally {
      setBusy("");
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="Reduce access safely"
        title="Recommendation center"
        description="Use observed traffic, application intent, and path analysis to propose smaller rules without breaking legitimate connectivity."
        actions={<><EvidenceMode data={intelligence.data} /><span className="read-only-pill"><ShieldCheck size={14} /> Simulation first · no AWS writes</span></>}
      />
      <div className="feature-tabs">
        <button className={tab === "advisor" ? "active" : ""} onClick={() => setTab("advisor")}><WandSparkles size={15} />Rule advisor</button>
        <button className={tab === "hygiene" ? "active" : ""} onClick={() => setTab("hygiene")}><ListChecks size={15} />Hygiene center</button>
        <button className={tab === "iac" ? "active" : ""} onClick={() => setTab("iac")}><Code2 size={15} />IaC guardrails</button>
      </div>
      <WorkflowError message={workflow.error} />

      {tab === "advisor" ? (
        <div className="recommendation-layout">
          <section className="panel recommendation-index">
            <div className="panel-header"><div><h2>Proposed changes</h2><p>Ranked by risk removed and confidence</p></div><span className="version-chip">{recommendations.length} ready</span></div>
            {recommendations.map((recommendation) => {
              const status = workflow.records[recommendation.id]?.status ?? "proposed";
              return (
                <button className={selectedId === recommendation.id ? "active" : ""} onClick={() => { setSelectedId(recommendation.id); setSimulated(false); }} key={recommendation.id}>
                  <span className="recommendation-gain">−{recommendation.riskBefore - recommendation.riskAfter}</span>
                  <p><strong>{recommendation.groupName}</strong><span>{recommendation.currentRule}</span><small>{recommendation.owner} · {recommendation.confidence}% confidence</small></p>
                  <em className={`workflow-status status-${status}`}>{status}</em>
                </button>
              );
            })}
          </section>
          {selected ? <section className="panel recommendation-detail">
            <header>
              <div><span className="version-chip">{selected.confidence}% confidence</span><h2>{selected.groupName}</h2><p>{selected.application} · {selected.owner}</p></div>
              <div className="risk-transition"><span><small>Current</small><strong>{selected.riskBefore}</strong></span><ArrowRight size={17} /><span className={simulated ? "projected" : ""}><small>Projected</small><strong>{simulated ? selected.riskAfter : "—"}</strong></span></div>
            </header>
            <div className="rule-diff">
              <div className="removed"><span>Remove</span><code>− {selected.currentRule}</code></div>
              {selected.proposedRules.map((rule) => <div className="added" key={rule}><span>Add</span><code>+ {rule}</code></div>)}
            </div>
            <section className="recommendation-basis">
              <h3>Why Gatewatch recommends this</h3>
              {selected.basis.map((basis) => <div key={basis}><CircleCheck size={15} /><span>{basis}</span></div>)}
            </section>
            <div className="simulation-impact">
              <div><span>Observation window</span><strong>{selected.observationWindow}</strong></div>
              <div><span>Paths removed</span><strong>{simulated ? selected.pathsRemoved : "—"}</strong></div>
              <div><span>Traffic preserved</span><strong>{simulated ? `${selected.trafficPreserved}%` : "—"}</strong></div>
              <div><span>Risk reduction</span><strong>{simulated ? `${selected.riskBefore - selected.riskAfter} points` : "—"}</strong></div>
            </div>
            <div className="rollback-note"><RefreshCw size={15} /><p><strong>Rollback plan</strong><span>{selected.rollback}</span></p></div>
            <footer>
              <button className="button button-dark" onClick={() => { setSimulated(true); onToast("Read-only path and traffic simulation completed."); }}><Sparkles size={15} />{simulated ? "Simulation complete" : "Simulate change"}</button>
              <button className="button button-primary" disabled={!simulated || busy === selected.id || workflow.records[selected.id]?.status === "approved"} onClick={() => void updateRecommendation("approved")}><BadgeCheck size={15} />Approve proposal</button>
              <button className="button button-secondary" onClick={() => void updateRecommendation("dismissed")}>Dismiss</button>
            </footer>
          </section> : <section className="panel intel-empty"><ShieldCheck size={24} /><h2>No narrowing recommendation is ready</h2><p>Recommendations appear when the current AWS snapshot contains internet-wide rules.</p></section>}
        </div>
      ) : null}

      {tab === "hygiene" ? <HygieneCenter issues={intelligence.data.hygieneIssues} workflow={workflow} onToast={onToast} /> : null}
      {tab === "iac" ? <IacGuardrails changes={intelligence.data.iacChanges} workflow={workflow} onToast={onToast} /> : null}
    </>
  );
}

function HygieneCenter({
  issues,
  workflow,
  onToast,
}: {
  issues: typeof hygieneIssues;
  workflow: ReturnType<typeof useWorkflows>;
  onToast: ToastHandler;
}) {
  const [type, setType] = useState("all");
  const filtered = issues.filter((item) => type === "all" || item.type === type);
  async function schedule(id: string) {
    const item = issues.find((issue) => issue.id === id)!;
    const saved = await workflow.save({ id, kind: "hygiene", subjectId: item.resource, status: "scheduled", owner: "Cloud Operations", note: item.recommendation, ticketRef: `CLOUD-${3100 + issues.indexOf(item)}`, expiresAt: "", payload: { type: item.type, count: item.count } });
    if (!saved) return;
    onToast(`${item.type} cleanup scheduled.`);
  }
  return (
    <section className="panel hygiene-panel">
      <div className="panel-header"><div><h2>Security-group hygiene</h2><p>Remove inventory noise, ineffective rules, stale references, and quota pressure</p></div><label className="filter-select"><Filter size={14} /><select value={type} onChange={(event) => setType(event.target.value)}><option value="all">All issue types</option>{[...new Set(issues.map((item) => item.type))].map((value) => <option key={value}>{value}</option>)}</select></label></div>
      <div className="hygiene-summary">{issues.slice(0, 4).map((item) => <div key={item.id}><strong>{item.count}</strong><span>{item.type}</span></div>)}</div>
      <div className="hygiene-list">
        {filtered.map((item) => {
          const status = workflow.records[item.id]?.status ?? "open";
          return <article key={item.id}><span className="hygiene-icon"><Boxes size={17} /></span><p><strong>{item.type} · {item.resource}</strong><span>{item.impact}</span><small>{item.account}</small></p><div><strong>{item.recommendation}</strong><span className={`workflow-status status-${status}`}>{status}</span></div><button className="button button-secondary" disabled={status === "scheduled"} onClick={() => void schedule(item.id)}>{status === "scheduled" ? <Check size={14} /> : <Clock3 size={14} />}{status === "scheduled" ? "Scheduled" : "Schedule cleanup"}</button></article>;
        })}
      </div>
    </section>
  );
}

function IacGuardrails({
  changes,
  workflow,
  onToast,
}: {
  changes: typeof iacChanges;
  workflow: ReturnType<typeof useWorkflows>;
  onToast: ToastHandler;
}) {
  const [selectedId, setSelectedId] = useState("");
  const selected = changes.find((change) => change.id === selectedId) ?? changes[0] ?? null;
  const [uploads, setUploads] = useState<Array<{ id: string; digest: string; size: number; review: IacFileReview }>>([]);
  const [dragging, setDragging] = useState(false);
  const [processing, setProcessing] = useState(false);
  const [uploadError, setUploadError] = useState("");
  const [selectedGroupKey, setSelectedGroupKey] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<"all" | IacSeverity>("all");
  const batch = useMemo(() => consolidateInfrastructureReviews(uploads.map((upload) => upload.review)), [uploads]);
  const filteredGroups = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return batch.groups.filter((group) => {
      const searchable = [group.name, group.key, group.vpc, group.description, ...group.fileNames, ...group.resourceAddresses, ...group.rules.flatMap((rule) => [rule.protocol, ...rule.sources]), ...group.issues.flatMap((issue) => [issue.title, issue.description])].join(" ").toLowerCase();
      return (!normalized || searchable.includes(normalized)) && (severity === "all" || group.issues.some((issue) => issue.severity === severity));
    });
  }, [batch.groups, query, severity]);
  const selectedGroup = filteredGroups.find((group) => group.key === selectedGroupKey) ?? filteredGroups[0] ?? null;

  async function digestFile(file: File) {
    const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
    return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
  }

  async function processFiles(files: File[]) {
    setUploadError("");
    if (!files.length) return;
    if (files.length > MAX_IAC_FILES || files.length + uploads.length > MAX_IAC_FILES) {
      setUploadError(`Review at most ${MAX_IAC_FILES} infrastructure files in one session.`);
      return;
    }
    const totalSize = files.reduce((sum, file) => sum + file.size, 0);
    if (totalSize > 50 * 1024 * 1024) {
      setUploadError("The selected batch is larger than 50 MB. Split it into smaller reviews.");
      return;
    }
    setProcessing(true);
    try {
      const known = new Set(uploads.map((upload) => upload.digest));
      const next: typeof uploads = [];
      let duplicates = 0;
      for (const file of files) {
        try {
          if (file.size > MAX_IAC_FILE_BYTES) {
            next.push({ id: crypto.randomUUID(), digest: "", size: file.size, review: { name: file.name.slice(0, 240), status: "rejected", resourceCount: 0, ruleCount: 0, warnings: [], error: "The infrastructure file is larger than 5 MB.", groups: [] } });
            continue;
          }
          const digest = await digestFile(file);
          if (known.has(digest)) { duplicates += 1; continue; }
          known.add(digest);
          next.push({ id: crypto.randomUUID(), digest, size: file.size, review: reviewInfrastructureFile(file.name, await file.text()) });
        } catch {
          next.push({ id: crypto.randomUUID(), digest: "", size: file.size, review: { name: file.name.slice(0, 240), status: "rejected", resourceCount: 0, ruleCount: 0, warnings: [], error: "The browser could not read this file. Check its permissions and try again.", groups: [] } });
        }
      }
      const projectedRules = [...uploads, ...next].reduce((sum, upload) => sum + upload.review.ruleCount, 0);
      if (projectedRules > MAX_IAC_BATCH_RULES) {
        setUploadError(`This session is limited to ${MAX_IAC_BATCH_RULES.toLocaleString()} normalized rules. Split the review into smaller batches.`);
        return;
      }
      setUploads((current) => [...current, ...next]);
      const parsed = next.filter((upload) => upload.review.status === "parsed").length;
      const rejected = next.length - parsed;
      onToast(`IaC review processed ${files.length} file${files.length === 1 ? "" : "s"}: ${parsed} parsed, ${rejected} rejected, ${duplicates} duplicate${duplicates === 1 ? "" : "s"}.`);
    } finally {
      setProcessing(false);
    }
  }

  function exportReview() {
    downloadCsv("gatewatch-iac-security-review.csv", [
      ["Verdict", "Risk", "Exposure", "Security group", "Resource address", "Files", "Severity", "Issue", "Rule", "Source", "Location", "Recommendation"],
      ...filteredGroups.flatMap((group) => group.issues.map((issue) => {
        const rule = group.rules.find((item) => item.id === issue.ruleId);
        return [group.verdict, String(group.riskScore), group.exposure, group.name, group.resourceAddresses.join("; "), group.fileNames.join("; "), issue.severity, issue.title, rule ? `${rule.direction} ${rule.protocol} ${rule.fromPort ?? "all"}-${rule.toPort ?? "all"}` : "", rule?.sources.join("; ") ?? "", `${issue.fileName}:${issue.line}`, issue.recommendation];
      })),
    ]);
    onToast(`Exported ${filteredGroups.length} consolidated IaC security-group review${filteredGroups.length === 1 ? "" : "s"}.`);
  }

  async function setGuardrail(status: "enabled" | "monitor") {
    if (!selected) return;
    const saved = await workflow.save({ id: `guardrail-${selected.id}`, kind: "iac-guardrail", subjectId: selected.repository, status, owner: "Cloud Security", note: selected.policy, ticketRef: selected.pullRequest, expiresAt: "", payload: { verdict: selected.verdict } });
    if (!saved) return;
    onToast(`${selected.policy} is now ${status === "enabled" ? "enforced" : "monitor-only"}.`);
  }
  return (
    <div className="iac-review-workspace">
      <section className="panel iac-upload-panel">
        <div className="panel-header"><div><h2>Review CloudFormation and Terraform</h2><p>Parse proposed security groups locally without executing templates, providers, modules, or hooks</p></div><span className="read-only-pill"><ShieldCheck size={13} />Local · read only</span></div>
        <label className={`iac-dropzone ${dragging ? "active" : ""} ${processing ? "processing" : ""}`} htmlFor="iac-review-files" onDragEnter={(event) => { event.preventDefault(); setDragging(true); }} onDragOver={(event) => { event.preventDefault(); setDragging(true); }} onDragLeave={(event) => { if (!event.currentTarget.contains(event.relatedTarget as Node)) setDragging(false); }} onDrop={(event) => { event.preventDefault(); setDragging(false); void processFiles([...event.dataTransfer.files]); }}>
          <input id="iac-review-files" className="sr-only" type="file" multiple accept=".yaml,.yml,.template,.json,.tf,.tf.json,application/json,text/yaml,text/plain" disabled={processing} onChange={(event) => { void processFiles([...(event.target.files ?? [])]); event.target.value = ""; }} />
          <span>{processing ? <RefreshCw className="spin" size={25} /> : <UploadCloud size={25} />}</span>
          <div><strong>{processing ? "Parsing infrastructure as data…" : dragging ? "Drop the IaC files here" : uploads.length ? "Add more infrastructure files" : "Drop CloudFormation and Terraform files"}</strong><p>YAML, JSON, HCL, and TF.JSON · up to {MAX_IAC_FILES} files · 5 MB each</p></div>
          <span className="button button-primary"><FileCode2 size={15} />Choose files</span>
        </label>
        <aside className="iac-safety-boundary"><ShieldAlert size={15} /><p><strong>No code execution</strong><span>Gatewatch never runs CloudFormation transforms, Terraform init/plan, provider plugins, external data sources, or module code. Unresolved expressions are reported for CI follow-up.</span></p></aside>
        {uploadError ? <div className="intel-error" role="alert"><CircleAlert size={15} />{uploadError}<button aria-label="Dismiss upload error" onClick={() => setUploadError("")}><X size={13} /></button></div> : null}
      </section>

      {uploads.length ? <>
        <section className="iac-review-metrics" aria-label="Infrastructure review summary">
          <article><strong>{batch.totals.parsedFiles}</strong><span>Files parsed</span></article>
          <article><strong>{batch.totals.groups}</strong><span>Security groups</span></article>
          <article><strong>{batch.totals.rules}</strong><span>Unique rules</span></article>
          <article className="critical"><strong>{batch.totals.critical}</strong><span>Critical issues</span></article>
          <article className="high"><strong>{batch.totals.high}</strong><span>High issues</span></article>
          <article><strong>{batch.totals.rejectedFiles}</strong><span>Rejected files</span></article>
        </section>
        <section className="panel iac-file-ledger">
          <div className="panel-header"><div><h2>File ledger</h2><p>Every parsed and rejected file remains visible for this browser session</p></div><div><button className="button button-secondary" disabled={!filteredGroups.length} onClick={exportReview}><Download size={14} />Export review</button><button className="button button-secondary button-danger-subtle" onClick={() => { if (!window.confirm("Clear every IaC file and review result from this browser session?")) return; setUploads([]); setSelectedGroupKey(""); setQuery(""); onToast("IaC review session cleared."); }}><Trash2 size={14} />Clear</button></div></div>
          <div>{uploads.map((upload) => <article className={`iac-file-row file-${upload.review.status}`} key={upload.id}><span>{upload.review.status === "parsed" ? <CircleCheck size={15} /> : <FileWarning size={15} />}</span><p><strong>{upload.review.name}</strong><small>{upload.review.status === "parsed" ? `${upload.review.format?.replaceAll("-", " ")} · ${upload.review.resourceCount} resources · ${upload.review.ruleCount} rules${upload.review.warnings.length ? ` · ${upload.review.warnings.length} warnings` : ""}` : upload.review.error}</small></p><em>{(upload.size / 1024).toFixed(1)} KB</em><button className="icon-button" aria-label={`Remove ${upload.review.name}`} onClick={() => setUploads((current) => current.filter((item) => item.id !== upload.id))}><X size={13} /></button></article>)}</div>
        </section>

        <div className="iac-review-layout">
          <section className="panel iac-review-list">
            <div className="iac-review-toolbar"><label className="table-search"><Search size={14} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search group, file, resource, port, source…" aria-label="Search IaC security group reviews" /></label><label className="filter-select"><Filter size={13} /><select value={severity} onChange={(event) => setSeverity(event.target.value as typeof severity)} aria-label="Filter IaC reviews by severity"><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label></div>
            <div className="iac-review-result-count"><strong>{filteredGroups.length}</strong> of {batch.groups.length} security groups</div>
            {filteredGroups.length ? filteredGroups.map((group) => <button className={selectedGroup?.key === group.key ? "active" : ""} onClick={() => setSelectedGroupKey(group.key)} key={group.key}><span className={`iac-verdict iac-${group.verdict}`}>{group.verdict}</span><p><strong>{group.name}</strong><span>{group.resourceAddresses.join(" · ")}</span><small>{group.fileNames.join(" · ")} · {group.rules.length} rules · {group.issues.length} issues</small></p><em>{group.riskScore}</em></button>) : <div className="intel-empty"><Search size={20} /><h2>No IaC findings match</h2><p>Clear the search or severity filter.</p></div>}
          </section>
          {selectedGroup ? <IacFileReviewDetail group={selectedGroup} /> : <section className="panel intel-empty"><ShieldCheck size={23} /><h2>No security-group resources found</h2><p>Parsed files will remain in the ledger even when they do not define or modify a security group.</p></section>}
        </div>
      </> : <section className="iac-first-run-grid">{[
        [FileCode2, "CloudFormation", "AWS::EC2::SecurityGroup plus standalone ingress and egress resources, YAML intrinsic tags, and JSON templates."],
        [Code2, "Terraform", "aws_security_group, legacy and modern standalone rules, nested ingress/egress blocks, variables, and TF.JSON."],
        [Target, "Actionable results", "One result per proposed security group with exact file, resource address, line, rule, risk, and remediation."],
      ].map(([Icon, title, description]) => { const FeatureIcon = Icon as LucideIcon; return <article className="panel" key={String(title)}><span><FeatureIcon size={19} /></span><h2>{String(title)}</h2><p>{String(description)}</p></article>; })}</section>}

      <details className="iac-ci-section" open={!uploads.length && Boolean(selected)}>
        <summary><GitPullRequest size={15} /><span><strong>Connected CI evaluations</strong><small>Pre-calculated results submitted by repository pipelines</small></span><ChevronRight size={14} /></summary>
        {!selected ? <section className="panel intel-empty"><GitPullRequest size={24} /><h2>No IaC provider connected</h2><p>Upload files above or connect a repository webhook/CI evaluation endpoint.</p></section> : <div className="iac-layout">
          <section className="panel iac-list">
            <div className="panel-header"><div><h2>Proposed infrastructure changes</h2><p>Pre-deployment exposure and intent evaluation</p></div><span className="pipeline-chip"><GitPullRequest size={13} />CI connected</span></div>
            {changes.map((change) => <button className={selected.id === change.id ? "active" : ""} onClick={() => setSelectedId(change.id)} key={change.id}><span className={`iac-verdict iac-${change.verdict.toLowerCase()}`}>{change.verdict}</span><p><strong>{change.repository} {change.pullRequest}</strong><span>{change.proposedChange}</span><small>{change.author} · {change.environment}</small></p><em>{change.currentRisk} → {change.projectedRisk}</em></button>)}
          </section>
          <section className="panel iac-detail">
            <header><span className={`iac-verdict iac-${selected.verdict.toLowerCase()}`}>{selected.verdict}</span><h2>{selected.repository} {selected.pullRequest}</h2><p>{selected.proposedChange}</p></header>
            <div className="iac-risk-row"><div><span>Current risk</span><strong>{selected.currentRisk}</strong></div><ArrowRight size={17} /><div><span>Projected risk</span><strong>{selected.projectedRisk}</strong></div><em className={selected.projectedRisk > selected.currentRisk ? "risk-up" : "risk-down"}>{selected.projectedRisk > selected.currentRisk ? "+" : ""}{selected.projectedRisk - selected.currentRisk}</em></div>
            <section><h3>Policy evaluation</h3><div className="policy-evaluation"><BookOpenCheck size={17} /><p><strong>{selected.policy}</strong><span>{selected.verdict === "Block" ? "The proposed state conflicts with approved application connectivity." : selected.verdict === "Pass" ? "The change reduces exposure and preserves required traffic." : "An expiring exception and security approval are required."}</span></p></div></section>
            <section><h3>Evidence</h3>{selected.evidence.map((evidence) => <div className="evidence-line" key={evidence}><Check size={14} />{evidence}</div>)}</section>
            <footer><button className="button button-primary" onClick={() => void setGuardrail("enabled")}><ShieldCheck size={15} />Enforce in CI</button><button className="button button-secondary" onClick={() => void setGuardrail("monitor")}><Eye size={15} />Monitor only</button><button className="button button-secondary" onClick={() => onToast("PR comment copied with projected paths, risk, and policy evidence.")}><GitPullRequest size={15} />Preview PR comment</button></footer>
          </section>
        </div>}
      </details>
    </div>
  );
}

function IacFileReviewDetail({ group }: { group: IacSecurityGroupReview }) {
  return <section className="panel iac-file-detail">
    <header><div><span className={`iac-verdict iac-${group.verdict}`}>{group.verdict}</span><h2>{group.name}</h2><p>{group.resourceAddresses.join(" · ")}</p></div><span className={`iac-review-risk risk-${group.riskScore >= 85 ? "critical" : group.riskScore >= 65 ? "high" : group.riskScore >= 35 ? "medium" : "low"}`}>{group.riskScore}<small>risk</small></span></header>
    <section className={`iac-exposure-card exposure-${group.exposure}`}><Globe2 size={17} /><div><strong>{group.exposure === "potential-internet" ? "Potential internet path" : group.exposure === "unknown" ? "Public reachability unresolved" : "No public ingress identified"}</strong><p>{group.exposureReason}</p><div className="iac-path-signals"><span className={group.pathSignals.internetGateway ? "present" : "missing"}>{group.pathSignals.internetGateway ? <Check size={10} /> : <X size={10} />}Internet gateway</span><span className={group.pathSignals.publicRoute ? "present" : "missing"}>{group.pathSignals.publicRoute ? <Check size={10} /> : <X size={10} />}Public route</span><span className={group.pathSignals.publicAttachment ? "present" : "missing"}>{group.pathSignals.publicAttachment ? <Check size={10} /> : <X size={10} />}Public attachment</span></div></div></section>
    <dl className="iac-resource-context"><div><dt>Files</dt><dd>{group.fileNames.join(", ")}</dd></div><div><dt>VPC</dt><dd>{group.vpc}</dd></div><div><dt>Attachments</dt><dd>{group.attachmentSignals.length ? group.attachmentSignals.join(", ") : "No attachment reference resolved"}</dd></div><div><dt>Definition</dt><dd>{group.description || "No group description"}</dd></div></dl>
    <section className="iac-issue-section"><div className="section-heading"><div><h3>Configuration issues</h3><p>Prioritized by likely impact if the proposed state is deployed</p></div><span>{group.issues.length}</span></div>{group.issues.length ? <div className="iac-issue-list">{group.issues.map((issue) => <article key={issue.id}><span className={`severity-badge severity-${issue.severity}`}><i />{issue.severity}</span><div><h4>{issue.title}</h4><code>{issue.fileName}:{issue.line} · {issue.resourceAddress}</code><p>{issue.description}</p><aside><Target size={13} />{issue.recommendation}</aside></div></article>)}</div> : <div className="iac-pass-state"><CircleCheck size={20} /><div><strong>No security-group issue detected</strong><p>The parsed rules passed the current static checks. Resolve all parser warnings and validate deployed reachability before approval.</p></div></div>}</section>
    <section className="iac-rule-section"><div className="section-heading"><div><h3>Normalized rules</h3><p>Duplicate rules across uploaded files are shown once</p></div><span>{group.rules.length}</span></div>{group.rules.length ? <div className="iac-rule-table"><div className="iac-rule-head"><span>Direction</span><span>Protocol / ports</span><span>Source</span><span>Location</span></div>{group.rules.map((rule) => <div key={rule.id}><strong>{rule.direction}</strong><code>{rule.protocol} · {rule.fromPort ?? "all"}{rule.toPort !== rule.fromPort ? `–${rule.toPort ?? "all"}` : ""}</code><span>{rule.sources.join(", ")}{rule.unresolved ? <em>unresolved</em> : null}</span><small>{rule.fileName}:{rule.line}</small></div>)}</div> : <div className="iac-pass-state"><FileCheck2 size={19} /><div><strong>No inline or standalone rules found</strong><p>The uploaded definition may create an empty group or supply rules through a module, dynamic block, transform, or separate file.</p></div></div>}</section>
  </section>;
}

export function DriftInboxView({
  onToast,
}: {
  onToast: ToastHandler;
}) {
  const workflow = useWorkflows(onToast);
  const intelligence = useIntelligenceData();
  const events = intelligence.data.driftEvents;
  const [severity, setSeverity] = useState("all");
  const [status, setStatus] = useState("open");
  const [selectedId, setSelectedId] = useState(events[0]?.id ?? "");
  const filtered = events.filter((event) => {
    const current = workflow.records[event.id]?.status ?? "new";
    return (severity === "all" || event.severity === severity) && (status === "all" || (status === "open" ? !["expected", "closed"].includes(current) : current === status));
  });
  const selected = events.find((item) => item.id === selectedId) ?? filtered[0] ?? events[0] ?? null;

  async function disposition(nextStatus: string) {
    if (!selected) return;
    const saved = await workflow.save({ id: selected.id, kind: "drift", subjectId: selected.groupId, status: nextStatus, owner: selected.owner, note: selected.reason, ticketRef: selected.ticket === "No ticket found" ? "" : selected.ticket, expiresAt: "", payload: { eventName: selected.eventName, riskDelta: selected.riskDelta } });
    if (!saved) return;
    onToast(`${selected.groupName} drift marked ${nextStatus}.`);
  }

  return (
    <>
      <PageHeader eyebrow="Continuous change governance" title="Exposure drift inbox" description="Investigate new broad access, policy bypasses, expired emergency changes, and reopened findings." actions={<><EvidenceMode data={intelligence.data} /><button className="button button-secondary" onClick={() => { downloadCsv("gatewatch-drift-inbox.csv", [["Time", "Group", "Actor", "Change", "Risk delta", "Severity"], ...filtered.map((item) => [item.occurredAt, item.groupName, item.actor, item.summary, String(item.riskDelta), item.severity])]); onToast("Drift inbox exported."); }}><Download size={15} />Export</button></>} />
      <section className="drift-summary">
        <article><span><TriangleAlert size={17} /></span><p><strong>{events.length}</strong><small>Attributed exposure changes</small></p></article>
        <article><span><Code2 size={17} /></span><p><strong>—</strong><small>IaC attribution unavailable</small></p></article>
        <article><span><RefreshCw size={17} /></span><p><strong>{events.filter((event) => event.recurrence > 1).length}</strong><small>Recurring exposures</small></p></article>
        <article><span><Clock3 size={17} /></span><p><strong>—</strong><small>Detection time not measured</small></p></article>
      </section>
      <WorkflowError message={workflow.error} />
      <div className="drift-layout">
        <section className="panel drift-index">
          <div className="intel-toolbar">
            <label className="filter-select"><ShieldAlert size={14} /><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option></select></label>
            <label className="filter-select"><Filter size={14} /><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="open">Open changes</option><option value="all">All statuses</option><option value="investigating">Investigating</option><option value="expected">Expected</option><option value="remediate">Remediate</option></select></label>
          </div>
          {filtered.length ? filtered.map((event) => {
            const current = workflow.records[event.id]?.status ?? "new";
            return <button className={selected.id === event.id ? "active" : ""} onClick={() => setSelectedId(event.id)} key={event.id}><span className={`severity-marker severity-${event.severity}`} /><p><strong>{event.groupName}</strong><span>{event.summary}</span><small>{event.actor} · {new Date(event.occurredAt).toLocaleString()}</small></p><span className={`workflow-status status-${current}`}>{current}</span><em>+{event.riskDelta}</em></button>;
          }) : <div className="intel-empty"><ShieldCheck size={22} /><h2>No attributed exposure drift</h2><p>CloudTrail attribution has not identified a new security-group exposure in the current evidence.</p></div>}
        </section>
        {selected ? <section className="panel drift-detail">
          <header><div><span className={`severity-badge severity-${selected.severity}`}><span />{selected.severity}</span><h2>{selected.eventName}</h2><p>{selected.groupName} · {selected.groupId}</p></div><span className="risk-delta">+{selected.riskDelta}<small>risk</small></span></header>
          <div className="drift-provenance"><div><span>Actor</span><strong>{selected.actor}</strong><small>{selected.actorType}</small></div><div><span>Channel</span><strong>{selected.channel}</strong><small>{selected.ticket}</small></div><div><span>Recurrence</span><strong>{selected.recurrence} occurrence{selected.recurrence === 1 ? "" : "s"}</strong><small>{selected.reason}</small></div></div>
          <div className="rule-diff"><div className="removed"><span>Before</span><code>− {selected.previousRule}</code></div><div className="added risk-add"><span>After</span><code>+ {selected.currentRule}</code></div></div>
          <section className="drift-reason"><AlertTriangle size={17} /><p><strong>Why this needs review</strong><span>{selected.reason}. CloudTrail confirms the API call succeeded; AWS Config confirms the resulting rule remains active.</span></p></section>
          <footer><button className="button button-primary" onClick={() => void disposition("investigating")}><Search size={15} />Investigate</button><button className="button button-secondary" onClick={() => void disposition("expected")}><Check size={15} />Mark expected</button><button className="button button-danger" onClick={() => void disposition("remediate")}><Target size={15} />Request remediation</button></footer>
        </section> : <section className="panel intel-empty"><CircleAlert size={24} /><h2>Change evidence is incomplete</h2><p>Connect CloudTrail and AWS Config history to compare before and after rules.</p></section>}
      </div>
    </>
  );
}

export function OwnerGovernanceView({
  onToast,
}: {
  onToast: ToastHandler;
}) {
  const workflow = useWorkflows(onToast);
  const intelligence = useIntelligenceData();
  const queues = intelligence.data.ownerQueues;
  const exposures = intelligence.data.exposureRecords;
  const [tab, setTab] = useState<"owners" | "exceptions" | "controls">("owners");
  const [exceptionOpen, setExceptionOpen] = useState(false);
  const [exceptionForm, setExceptionForm] = useState({ subjectId: "", owner: "", ticketRef: "", expiresAt: "", note: "", controls: "" });
  const storedExceptions = Object.values(workflow.records).filter((record) => record.kind === "exception");
  const combinedExceptions: ExceptionSeed[] = [
    ...(intelligence.data.mode === "demonstration" ? exceptionSeeds : []).map((seed) => {
      const stored = workflow.records[seed.id];
      return stored ? { ...seed, status: stored.status as ExceptionSeed["status"], expiresAt: stored.expiresAt, ticketRef: stored.ticketRef, justification: stored.note, owner: stored.owner } : seed;
    }),
    ...storedExceptions.filter((record) => !exceptionSeeds.some((seed) => seed.id === record.id)).map((record) => ({
      id: record.id,
      subjectId: record.subjectId,
      groupName: String(record.payload.groupName ?? record.subjectId),
      owner: record.owner,
      status: record.status as ExceptionSeed["status"],
      expiresAt: record.expiresAt,
      ticketRef: record.ticketRef,
      justification: record.note,
      compensatingControls: Array.isArray(record.payload.controls) ? record.payload.controls.map(String) : [],
      approver: "Pending",
    })),
  ];

  async function ownerAction(queue: (typeof ownerQueues)[number], status: string) {
    const saved = await workflow.save({ id: queue.id, kind: "owner-task", subjectId: queue.application, status, owner: queue.owner, note: `${queue.openFindings} findings due ${queue.dueDate}`, ticketRef: "", expiresAt: queue.dueDate, payload: { findings: queue.openFindings, risk: queue.risk } });
    if (!saved) return;
    onToast(`${queue.owner} work queue marked ${status}.`);
  }

  async function submitException() {
    const id = `exception-${crypto.randomUUID()}`;
    const saved = await workflow.save({ id, kind: "exception", subjectId: exceptionForm.subjectId, status: "requested", owner: exceptionForm.owner, note: exceptionForm.note, ticketRef: exceptionForm.ticketRef, expiresAt: exceptionForm.expiresAt, payload: { groupName: exposures.find((record) => record.id === exceptionForm.subjectId)?.groupName ?? exceptionForm.subjectId, controls: exceptionForm.controls.split("\n").map((value) => value.trim()).filter(Boolean) } });
    if (!saved) return;
    setExceptionOpen(false);
    setExceptionForm({ subjectId: "", owner: "", ticketRef: "", expiresAt: "", note: "", controls: "" });
    onToast("Exception request created and routed for independent approval.");
  }

  async function exceptionStatus(item: ExceptionSeed, status: string) {
    const saved = await workflow.save({ id: item.id, kind: "exception", subjectId: item.subjectId, status, owner: item.owner, note: item.justification, ticketRef: item.ticketRef, expiresAt: item.expiresAt, payload: { groupName: item.groupName, controls: item.compensatingControls } });
    if (!saved) return;
    onToast(`${item.groupName} exception marked ${status}.`);
  }

  return (
    <>
      <PageHeader eyebrow="Ownership and assurance" title="Owner governance" description="Route evidence to accountable teams, control temporary exceptions, and reconcile Gatewatch findings with native security controls." actions={<><EvidenceMode data={intelligence.data} />{tab === "exceptions" ? <button className="button button-primary" onClick={() => setExceptionOpen(true)}><Plus size={15} />Request exception</button> : null}</>} />
      <div className="feature-tabs">
        <button className={tab === "owners" ? "active" : ""} onClick={() => setTab("owners")}><Users size={15} />Owner inbox</button>
        <button className={tab === "exceptions" ? "active" : ""} onClick={() => setTab("exceptions")}><ShieldEllipsis size={15} />Exceptions</button>
        <button className={tab === "controls" ? "active" : ""} onClick={() => setTab("controls")}><BookOpenCheck size={15} />Control mapping</button>
      </div>
      <WorkflowError message={workflow.error} />
      {tab === "owners" ? (
        <>
          <section className="owner-scoreboard"><div><strong>{queues.reduce((sum, queue) => sum + queue.openFindings, 0)}</strong><span>Assigned findings</span></div><div><strong>{queues.reduce((sum, queue) => sum + queue.critical + queue.overdue, 0)}</strong><span>Critical or overdue</span></div><div><strong>—</strong><span>Mean accept time not measured</span></div><div><strong>{queues.length ? Math.round(queues.reduce((sum, queue) => sum + queue.coverage, 0) / queues.length) : 0}%</strong><span>Evidence coverage</span></div></section>
          <section className="panel owner-inbox">
            <div className="owner-row owner-head"><span>Owner and application</span><span>Findings</span><span>SLA</span><span>Evidence</span><span>Workflow</span></div>
            {queues.map((queue) => {
              const state = workflow.records[queue.id]?.status ?? "open";
              return <article className="owner-row" key={queue.id}><div className="owner-identity"><span>{queue.owner.slice(0, 2).toUpperCase()}</span><p><strong>{queue.owner}</strong><small>{queue.application} · {queue.email}</small></p></div><div className="owner-findings"><strong>{queue.openFindings}</strong><span>{queue.critical} critical</span></div><div className={queue.overdue ? "sla-overdue" : ""}><strong>{queue.dueDate}</strong><span>{queue.overdue ? `${queue.overdue} overdue` : `${queue.oldestAge}d oldest`}</span></div><div><strong>{queue.coverage}%</strong><span>coverage</span></div><div className="owner-actions"><span className={`workflow-status status-${state}`}>{state}</span><button className="button button-secondary" disabled={state === "accepted"} onClick={() => void ownerAction(queue, "accepted")}><UserRoundCheck size={14} />Accept</button></div></article>;
            })}
          </section>
        </>
      ) : null}
      {tab === "exceptions" ? (
        <section className="exception-grid">
          {combinedExceptions.map((item) => <article className={`panel exception-card exception-${item.status}`} key={item.id}><header><span><ShieldEllipsis size={17} /></span><div><h2>{item.groupName}</h2><p>{item.subjectId} · {item.owner}</p></div><span className={`workflow-status status-${item.status}`}>{item.status}</span></header><div className="exception-expiry"><Clock3 size={15} /><p><span>Expires</span><strong>{item.expiresAt}</strong></p><em>{item.ticketRef}</em></div><p className="exception-justification">{item.justification}</p><div className="control-chips">{item.compensatingControls.map((control) => <span key={control}><Check size={11} />{control}</span>)}</div><footer><small>Approver: {item.approver}</small>{item.status === "requested" ? <><button className="button button-primary" onClick={() => void exceptionStatus(item, "approved")}>Approve</button><button className="button button-secondary" onClick={() => void exceptionStatus(item, "rejected")}>Reject</button></> : item.status === "approved" ? <button className="button button-danger" onClick={() => void exceptionStatus(item, "revoked")}>Revoke</button> : null}</footer></article>)}
        </section>
      ) : null}
      {tab === "controls" ? <ControlMappingView controls={intelligence.data.controlMappings} /> : null}
      {exceptionOpen ? (
        <div className="modal-layer" role="dialog" aria-modal="true" aria-labelledby="exception-title">
          <button className="modal-scrim" aria-label="Close exception request" onClick={() => setExceptionOpen(false)} />
          <div className="intel-modal">
            <div className="modal-header"><div><p>Time-bound access</p><h2 id="exception-title">Request exception</h2><span>Independent approval and expiration are required</span></div><button className="icon-button" aria-label="Close" onClick={() => setExceptionOpen(false)}><X size={18} /></button></div>
            <div className="modal-body">
              <div className="form-grid-two">
                <label className="form-field"><span>Security group</span><select value={exceptionForm.subjectId} onChange={(event) => { const record = exposures.find((item) => item.id === event.target.value); setExceptionForm((current) => ({ ...current, subjectId: event.target.value, owner: record?.owner ?? "" })); }}><option value="">Choose a group</option>{exposures.map((record) => <option value={record.id} key={record.id}>{record.groupName} · {record.account} · {record.region}</option>)}</select></label>
                <label className="form-field"><span>Accountable owner</span><input value={exceptionForm.owner} onChange={(event) => setExceptionForm((current) => ({ ...current, owner: event.target.value }))} /></label>
                <label className="form-field"><span>Ticket or incident</span><input value={exceptionForm.ticketRef} onChange={(event) => setExceptionForm((current) => ({ ...current, ticketRef: event.target.value }))} placeholder="SEC-1234" /></label>
                <label className="form-field"><span>Expires</span><input type="date" min={new Date().toISOString().slice(0, 10)} value={exceptionForm.expiresAt} onChange={(event) => setExceptionForm((current) => ({ ...current, expiresAt: event.target.value }))} /></label>
              </div>
              <label className="form-field"><span>Business justification</span><textarea value={exceptionForm.note} onChange={(event) => setExceptionForm((current) => ({ ...current, note: event.target.value }))} placeholder="Why must this access remain broader than policy?" maxLength={2000} /></label>
              <label className="form-field"><span>Compensating controls <em>One per line</em></span><textarea value={exceptionForm.controls} onChange={(event) => setExceptionForm((current) => ({ ...current, controls: event.target.value }))} placeholder={"Session recording\nMFA required\nDaily traffic review"} /></label>
              <WorkflowError message={workflow.error} />
            </div>
            <div className="modal-footer"><button className="button button-secondary" onClick={() => setExceptionOpen(false)}>Cancel</button><button className="button button-primary" disabled={!exceptionForm.subjectId || !exceptionForm.ticketRef || !exceptionForm.expiresAt || exceptionForm.note.length < 12} onClick={() => void submitException()}><ShieldEllipsis size={15} />Submit request</button></div>
          </div>
        </div>
      ) : null}
    </>
  );
}

function ControlMappingView({ controls }: { controls: typeof controlMappings }) {
  return (
    <section className="panel control-mapping">
      <div className="panel-header"><div><h2>Native control reconciliation</h2><p>AWS Security Hub result compared with effective Gatewatch evidence</p></div><span className="version-chip">{controls.length} controls</span></div>
      <div className="control-head"><span>Control</span><span>Frameworks</span><span>AWS result</span><span>Gatewatch</span><span>Affected</span></div>
      {controls.map((control) => <article key={control.id}><div><span className="control-id">{control.id}</span><p><strong>{control.title}</strong><small>{control.explanation}</small></p></div><div className="framework-chips">{control.framework.map((framework) => <span key={framework}>{framework}</span>)}</div><span className={`native-result native-${control.nativeResult.toLowerCase().replaceAll(" ", "-")}`}>{control.nativeResult}</span><span className={`gatewatch-result result-${control.gatewatchResult.toLowerCase()}`}>{control.gatewatchResult}</span><strong>{control.affected}</strong></article>)}
    </section>
  );
}

export function ProgramMetricsView({
  onToast,
}: {
  onToast: ToastHandler;
}) {
  const [period, setPeriod] = useState("6 months");
  const [metrics, setMetrics] = useState<{
    current: Record<string, number>;
    source: { coveragePercent: number; generatedAt: string };
    history: Array<{
      periodStart: string;
      metrics: Record<string, number>;
      evidenceCoverage: number;
    }>;
  } | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    fetch("/api/metrics", { cache: "no-store" })
      .then(async (response) => {
        const payload = (await response.json()) as typeof metrics & { error?: string };
        if (!response.ok || !payload) throw new Error(payload?.error ?? "Metrics are unavailable.");
        return payload;
      })
      .then((payload) => {
        if (active) setMetrics(payload);
      })
      .catch((caught) => {
        if (active) setError(caught instanceof Error ? caught.message : "Metrics are unavailable.");
      });
    return () => {
      active = false;
    };
  }, []);
  const visibleHistory = (metrics?.history ?? []).slice(
    0,
    period === "30 days" ? 4 : period === "90 days" ? 12 : 24,
  ).reverse();
  const maxWide = Math.max(
    1,
    ...visibleHistory.map((item) => item.metrics.internetWideRules ?? 0),
  );
  const current = metrics?.current ?? {};
  function exportMetrics() {
    downloadCsv("gatewatch-program-report.csv", [
      ["Date", "Internet-wide rules", "Reachable critical", "Evidence incomplete", "Overdue", "Coverage"],
      ...visibleHistory.map((item) => [
        item.periodStart,
        String(item.metrics.internetWideRules ?? 0),
        String(item.metrics.reachableCritical ?? 0),
        String(item.metrics.evidenceIncomplete ?? 0),
        String(item.metrics.overdue ?? 0),
        String(item.evidenceCoverage),
      ]),
    ]);
    onToast("Executive program report exported from historical metrics.");
  }
  return (
    <>
      <PageHeader eyebrow="Security program outcomes" title="Program metrics" description="Historical outcomes are recorded from immutable AWS snapshots and current workflow state." actions={<><label className="filter-select"><Clock3 size={14} /><select value={period} onChange={(event) => setPeriod(event.target.value)}><option>6 months</option><option>90 days</option><option>30 days</option></select></label><button className="button button-primary" onClick={exportMetrics} disabled={!metrics}><Download size={15} />Export report</button></>} />
      {error ? <WorkflowError message={error} /> : null}
      <section className="program-scorecards">
        <article className="scorecard-good"><span><TrendingDown size={18} /></span><p><small>Internet-wide rules</small><strong>{current.internetWideRules ?? "—"}</strong><em>Current AWS snapshot</em></p></article>
        <article><span><Globe2 size={18} /></span><p><small>Reachable critical</small><strong>{current.reachableCritical ?? "—"}</strong><em>Verified route evidence only</em></p></article>
        <article><span><CircleAlert size={18} /></span><p><small>Evidence incomplete</small><strong>{current.evidenceIncomplete ?? "—"}</strong><em>Needs additional sources</em></p></article>
        <article><span><Users size={18} /></span><p><small>Owned groups</small><strong>{current.ownedGroups ?? "—"}</strong><em>{current.securityGroups ?? 0} total groups</em></p></article>
        <article><span><ShieldEllipsis size={18} /></span><p><small>Accepted risk</small><strong>{current.acceptedRisk ?? "—"}</strong><em>{current.overdue ?? 0} overdue</em></p></article>
      </section>
      <div className="program-grid">
        <section className="panel exposure-trend">
          <div className="panel-header"><div><h2>Exposure history</h2><p>One point per collected AWS snapshot</p></div><span className="version-chip">{visibleHistory.length} snapshots</span></div>
          <div className="trend-chart">
            {visibleHistory.map((item) => <div className="trend-column" key={`${item.periodStart}-${item.evidenceCoverage}`}><div className="trend-bars"><span className="bar-wide" style={{ height: `${((item.metrics.internetWideRules ?? 0) / maxWide) * 100}%` }} title={`${item.metrics.internetWideRules ?? 0} internet-wide rules`} /><span className="bar-critical" style={{ height: `${((item.metrics.reachableCritical ?? 0) / maxWide) * 100}%` }} title={`${item.metrics.reachableCritical ?? 0} reachable critical assets`} /></div><strong>{item.periodStart.slice(5)}</strong></div>)}
          </div>
          <div className="chart-legend"><span><i className="legend-wide" />Internet-wide rules</span><span><i className="legend-critical" />Reachable critical assets</span></div>
        </section>
        <section className="panel outcome-panel">
          <div className="panel-header"><div><h2>Current evidence quality</h2><p>Metrics are bounded by collection completeness</p></div></div>
          {([
            ["Snapshot coverage", `${metrics?.source.coveragePercent ?? 0}%`, metrics?.source.generatedAt ?? "Unavailable", Target],
            ["Total risk points", String(current.riskPoints ?? "—"), "Current findings", Route],
            ["Follow-ups overdue", String(current.overdue ?? "—"), "Owner action required", Clock3],
            ["Evidence incomplete", String(current.evidenceIncomplete ?? "—"), "Negative conclusions are limited", TriangleAlert],
          ] as Array<[string, string, string, LucideIcon]>).map(([label, value, helper, Icon]) => <div className="outcome-row" key={label}><span><Icon size={16} /></span><p><strong>{label}</strong><small>{helper}</small></p><em>{value}</em></div>)}
        </section>
        <section className="panel program-highlights">
          <div className="panel-header"><div><h2>Leadership summary</h2><p>Generated from current evidence</p></div><BriefcaseBusiness size={18} /></div>
          <p>{current.internetWideRules ?? 0} internet-wide rules are present across {current.securityGroups ?? 0} security groups. {current.evidenceIncomplete ?? 0} findings lack sufficient evidence for a definitive reachability conclusion.</p>
          <div><CircleCheck size={15} /><span>{current.ownedGroups ?? 0} security groups have an accountable owner.</span></div>
          <div><CircleCheck size={15} /><span>Historical points are retained per immutable snapshot.</span></div>
          {(current.overdue ?? 0) > 0 ? <div className="highlight-attention"><AlertTriangle size={15} /><span>{current.overdue} follow-ups are overdue.</span></div> : null}
        </section>
      </div>
    </>
  );
}
