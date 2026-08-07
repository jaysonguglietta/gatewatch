"use client";

import {
  Activity, AlertTriangle, Archive, BellRing, Building2, CheckCircle2, Clock3, Database,
  Download, FileClock, GitMerge, Globe2, Pause, Play, Plus, RefreshCw, Save,
  Search, ShieldCheck, SlidersHorizontal, Trash2, XCircle,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { defaultRiskWeights, type RiskWeights } from "../lib/organization-operations";

type Tab = "overview" | "accounts" | "correlation" | "monitors" | "exports" | "controls";
type Account = { accountId: string; accountName: string; organizationalUnit: string; environment: string; businessUnit: string; owner: string; groupCount: number; regionCount: number; findingCount: number; criticalCount: number; status: string };
type Mapping = { id: string; sourceIdentifier: string; securityGroupArn: string; confidence: number; reason: string; status: string; createdBy: string; updatedAt: string };
type Monitor = { id: string; name: string; query: string; groupBy: string; schedule: string; triggerMode: string; destinations: string[]; visibility: string; owner: string; status: string; lastRunAt: string; nextRunAt: string; lastMatchCount: number };
type ExportJob = { id: string; name: string; format: string; schedule: string; status: string; rowCount: number; requestedBy: string; createdAt: string; completedAt: string };
type Hold = { id: string; name: string; scopeType: string; scopeValue: string; reason: string; status: string; requestedBy: string; createdAt: string };
type RiskPolicy = { id: string; name: string; status: string; weights: RiskWeights; thresholds: Record<string, number>; updatedAt: string };
type Payload = {
  generatedAt: string;
  summary: { accounts: number; organizationalUnits: number; activeMappings: number; activeMonitors: number; queuedExports: number; activeLegalHolds: number };
  source: { complete?: boolean; generatedAt?: string; coveragePercent?: number };
  accounts: Account[]; mappings: Mapping[]; monitors: Monitor[];
  monitorRuns: Array<{ id: string; monitorId: string; matchCount: number; enteredCount: number; exitedCount: number; createdAt: string }>;
  exports: ExportJob[]; legalHolds: Hold[]; riskPolicies: RiskPolicy[];
  retention: { rawEvidenceDays: number; normalizedEvidenceDays: number; auditDays: number; exportDays: number };
  temporal: Array<{ state: string; count: number; recurring: number }>;
  evidenceHealth: Array<{ sourceId: string; accountId: string; recordCount: number; latest: string }>;
  regionHeatmap: Array<{ region: string; accounts: number; groups: number; findings: number }>;
  capabilities: { parquetWorker: boolean };
};

const tabs: Array<{ id: Tab; label: string; icon: typeof Activity }> = [
  { id: "overview", label: "Operations overview", icon: Activity },
  { id: "accounts", label: "Account catalog", icon: Building2 },
  { id: "correlation", label: "Correlation", icon: GitMerge },
  { id: "monitors", label: "Monitors", icon: BellRing },
  { id: "exports", label: "Exports", icon: Download },
  { id: "controls", label: "Data controls", icon: SlidersHorizontal },
];

function when(value: string) {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(date);
}

export default function OrganizationOperationsView({ onToast }: { onToast: (message: string) => void }) {
  const [tab, setTab] = useState<Tab>("overview");
  const [data, setData] = useState<Payload | null>(null);
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState("");
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [selectedAccount, setSelectedAccount] = useState<Account | null>(null);

  async function load() {
    setLoading(true); setError("");
    try {
      const response = await fetch("/api/organization-operations", { cache: "no-store" });
      const payload = await response.json() as Payload & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Organization operations could not be loaded.");
      setData(payload);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Organization operations could not be loaded.");
    } finally { setLoading(false); }
  }

  async function act(action: string, body: Record<string, unknown>, success: string, reload = true) {
    setWorking(action); setError("");
    try {
      const response = await fetch("/api/organization-operations", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ action, ...body }) });
      const payload = await response.json() as { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "The operation failed.");
      onToast(success);
      if (reload) await load();
      return true;
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : "The operation failed.";
      setError(message); onToast(message); return false;
    } finally { setWorking(""); }
  }

  useEffect(() => { const timer = window.setTimeout(() => void load(), 0); return () => window.clearTimeout(timer); }, []);

  const accounts = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return (data?.accounts ?? []).filter((account) => !needle || [account.accountId, account.accountName, account.organizationalUnit, account.environment, account.businessUnit, account.owner].join(" ").toLowerCase().includes(needle));
  }, [data, query]);

  return <>
    <div className="page-header">
      <div><p className="eyebrow">Organization-scale evidence operations</p><h1>Organization operations</h1><p>Operate account context, evidence correlation, recurring detection, governed exports, retention, and risk policy across the AWS organization.</p></div>
      <div className="page-actions"><button className="button button-secondary" onClick={() => void load()} disabled={loading}><RefreshCw size={15} className={loading ? "spin" : ""} />Refresh</button><button className="button button-primary" onClick={() => void act("sync-accounts", {}, "AWS account catalog synchronized.")} disabled={Boolean(working)}><Building2 size={15} />Sync accounts</button></div>
    </div>
    {error ? <div className="daily-error" role="alert"><AlertTriangle size={17} /><p><strong>Operation needs attention</strong><span>{error}</span></p><button onClick={() => setError("")}>Dismiss</button></div> : null}
    <nav className="ops-tabs" aria-label="Organization operations sections">{tabs.map((item) => { const Icon = item.icon; return <button key={item.id} className={tab === item.id ? "active" : ""} onClick={() => setTab(item.id)}><Icon size={15} />{item.label}</button>; })}</nav>
    {loading && !data ? <section className="panel ops-loading"><RefreshCw className="spin" size={20} /><strong>Loading organization operating state…</strong></section> : null}
    {data && tab === "overview" ? <Overview data={data} /> : null}
    {data && tab === "accounts" ? <Accounts data={data} accounts={accounts} query={query} setQuery={setQuery} selected={selectedAccount} setSelected={setSelectedAccount} working={working} act={act} /> : null}
    {data && tab === "correlation" ? <Correlation mappings={data.mappings} evidence={data.evidenceHealth} working={working} act={act} /> : null}
    {data && tab === "monitors" ? <Monitors monitors={data.monitors} runs={data.monitorRuns} working={working} act={act} /> : null}
    {data && tab === "exports" ? <Exports jobs={data.exports} parquetWorker={data.capabilities.parquetWorker} working={working} act={act} /> : null}
    {data && tab === "controls" ? <Controls data={data} working={working} act={act} /> : null}
  </>;
}

function Overview({ data }: { data: Payload }) {
  const temporalTotal = data.temporal.reduce((sum, item) => sum + Number(item.count), 0);
  const maxFindings = Math.max(1, ...data.regionHeatmap.map((item) => item.findings));
  return <>
    <section className="ops-scorecards">
      {([
        ["AWS accounts", data.summary.accounts, `${data.summary.organizationalUnits} organizational units`, Building2],
        ["Active monitors", data.summary.activeMonitors, "Scheduled evidence queries", BellRing],
        ["Correlation mappings", data.summary.activeMappings, "Audited analyst decisions", GitMerge],
        ["Open findings", temporalTotal, `${data.temporal.reduce((sum, item) => sum + Number(item.recurring), 0)} recurring`, FileClock],
        ["Queued exports", data.summary.queuedExports, "Background and scheduled jobs", Download],
        ["Legal holds", data.summary.activeLegalHolds, "Retention overrides", Archive],
      ] as Array<[string, number, string, LucideIcon]>).map(([label, value, helper, Icon]) => <article className="panel" key={label}><span><Icon size={17} /></span><p><small>{label}</small><strong>{value.toLocaleString()}</strong><em>{helper}</em></p></article>)}
    </section>
    <section className={`ops-health-banner ${data.source.complete === false ? "partial" : "complete"}`}><ShieldCheck size={18} /><div><strong>{data.source.complete === false ? "Partial organization snapshot" : "Organization evidence current"}</strong><p>{data.source.coveragePercent ?? 100}% collection coverage · generated {when(data.source.generatedAt ?? data.generatedAt)}</p></div></section>
    <div className="ops-overview-grid">
      <section className="panel"><div className="panel-header"><div><h2>Coverage heatmap</h2><p>Account and evidence concentration by active region</p></div><Globe2 size={18} /></div><div className="ops-heatmap">{data.regionHeatmap.map((item) => <article key={item.region}><header><strong>{item.region}</strong><span>{item.accounts} accounts</span></header><div><i style={{ width: `${Math.max(8, item.findings / maxFindings * 100)}%` }} /></div><footer><span>{item.groups} groups</span><strong>{item.findings} findings</strong></footer></article>)}</div></section>
      <section className="panel"><div className="panel-header"><div><h2>Finding lifecycle</h2><p>First-seen, recurring, and resolved observation state</p></div><Clock3 size={18} /></div><div className="ops-lifecycle">{data.temporal.length ? data.temporal.map((item) => <article key={item.state}><span className={`ops-state ${item.state}`}>{item.state}</span><strong>{Number(item.count).toLocaleString()}</strong><small>{Number(item.recurring).toLocaleString()} recurring</small></article>) : <div className="ops-empty"><FileClock size={22} /><strong>No persisted observation windows yet</strong><p>The next live AWS findings refresh will create the temporal baseline.</p></div>}</div></section>
    </div>
  </>;
}

function Accounts({ accounts, query, setQuery, selected, setSelected, working, act }: { data: Payload; accounts: Account[]; query: string; setQuery: (value: string) => void; selected: Account | null; setSelected: (value: Account | null) => void; working: string; act: (action: string, body: Record<string, unknown>, success: string) => Promise<boolean> }) {
  const draft = selected;
  const setDraft = setSelected;
  return <section className="panel ops-table-panel"><div className="panel-header"><div><h2>AWS Organizations account catalog</h2><p>Business context used by search, grouping, ownership, monitors, and reporting</p></div><label className="ops-search"><Search size={15} /><input aria-label="Search account catalog" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search account, OU, owner…" /></label></div>
    <div className="table-wrap"><table><thead><tr><th>Account</th><th>Organizational unit</th><th>Environment</th><th>Business unit</th><th>Owner</th><th>Coverage</th><th></th></tr></thead><tbody>{accounts.map((account) => <tr key={account.accountId}><td><strong>{account.accountName}</strong><small>{account.accountId}</small></td><td>{account.organizationalUnit || "Unassigned"}</td><td><span className="version-chip">{account.environment}</span></td><td>{account.businessUnit || "Unassigned"}</td><td>{account.owner || "Unassigned"}</td><td><strong>{account.groupCount}</strong><small>{account.regionCount} regions · {account.findingCount} findings</small></td><td><button className="table-action" onClick={() => setSelected(account)}>Edit</button></td></tr>)}</tbody></table></div>
    {!accounts.length ? <div className="ops-empty"><Building2 size={22} /><strong>No matching accounts</strong><p>Change the search or synchronize the latest AWS inventory.</p></div> : null}
    {draft ? <div className="ops-editor" role="dialog" aria-modal="true" aria-labelledby="account-editor-title"><header><div><p className="eyebrow">AWS account {draft.accountId}</p><h2 id="account-editor-title">Organization context</h2></div><button aria-label="Close account editor" onClick={() => setSelected(null)}><XCircle size={19} /></button></header><div className="ops-form-grid">
      <label>Account name<input value={draft.accountName} onChange={(event) => setDraft({ ...draft, accountName: event.target.value })} /></label>
      <label>Organizational unit<input value={draft.organizationalUnit} onChange={(event) => setDraft({ ...draft, organizationalUnit: event.target.value })} /></label>
      <label>Environment<select value={draft.environment} onChange={(event) => setDraft({ ...draft, environment: event.target.value })}><option>Production</option><option>Staging</option><option>Development</option><option>Shared</option></select></label>
      <label>Business unit<input value={draft.businessUnit} onChange={(event) => setDraft({ ...draft, businessUnit: event.target.value })} /></label>
      <label className="span-two">Owner<input value={draft.owner} onChange={(event) => setDraft({ ...draft, owner: event.target.value })} /></label>
    </div><footer><button className="button button-secondary" onClick={() => setSelected(null)}>Cancel</button><button className="button button-primary" disabled={Boolean(working)} onClick={async () => { if (await act("account-update", draft, "Account context saved.")) setSelected(null); }}><Save size={15} />Save context</button></footer></div> : null}
  </section>;
}

function Correlation({ mappings, evidence, working, act }: { mappings: Mapping[]; evidence: Payload["evidenceHealth"]; working: string; act: (action: string, body: Record<string, unknown>, success: string) => Promise<boolean> }) {
  const [sourceIdentifier, setSourceIdentifier] = useState(""); const [arn, setArn] = useState(""); const [reason, setReason] = useState(""); const [confidence, setConfidence] = useState(90);
  return <div className="ops-two-column"><section className="panel"><div className="panel-header"><div><h2>Correlation workbench</h2><p>Resolve ambiguous evidence to one canonical security-group ARN</p></div><GitMerge size={18} /></div><form className="ops-stack" onSubmit={async (event) => { event.preventDefault(); if (await act("mapping-save", { sourceIdentifier, securityGroupArn: arn, reason, confidence }, "Evidence mapping saved.")) { setSourceIdentifier(""); setArn(""); setReason(""); } }}>
    <label>Unmatched source identifier<input required value={sourceIdentifier} onChange={(event) => setSourceIdentifier(event.target.value)} placeholder="eni-…, finding provider ID, or resource token" /></label>
    <label>Canonical security-group ARN<input required value={arn} onChange={(event) => setArn(event.target.value)} placeholder="arn:aws:ec2:us-east-1:123456789012:security-group/sg-…" /></label>
    <label>Confidence <strong>{confidence}%</strong><input type="range" min="1" max="100" value={confidence} onChange={(event) => setConfidence(Number(event.target.value))} /></label>
    <label>Audit reason<textarea required value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Explain the evidence used to establish this relationship." /></label>
    <button className="button button-primary" disabled={Boolean(working)}><Plus size={15} />Create mapping and reprocess</button>
  </form><div className="ops-quality"><h3>Unmatched evidence signals</h3>{evidence.length ? evidence.slice(0, 6).map((item) => <article key={`${item.sourceId}-${item.accountId}`}><Database size={15} /><p><strong>{item.sourceId}</strong><small>{item.accountId || "Account not resolved"} · latest {when(item.latest)}</small></p><span>{item.recordCount} records</span></article>) : <div className="ops-empty compact"><CheckCircle2 size={20} /><strong>No unmatched normalized evidence</strong></div>}</div></section>
    <section className="panel"><div className="panel-header"><div><h2>Analyst mappings</h2><p>Versioned, attributed, and reversible correlation decisions</p></div><span className="version-chip">{mappings.filter((item) => item.status === "active").length} active</span></div><div className="ops-list">{mappings.length ? mappings.map((mapping) => <article key={mapping.id} className={mapping.status !== "active" ? "muted" : ""}><header><strong>{mapping.sourceIdentifier}</strong><span className={`ops-state ${mapping.status}`}>{mapping.status}</span></header><code>{mapping.securityGroupArn}</code><p>{mapping.reason}</p><footer><span>{mapping.confidence}% confidence · {mapping.createdBy}</span>{mapping.status === "active" ? <button onClick={() => { if (window.confirm("Revoke this mapping? Future reprocessing will no longer use it.")) void act("mapping-revoke", { id: mapping.id }, "Mapping revoked."); }} disabled={Boolean(working)}><Trash2 size={13} />Revoke</button> : null}</footer></article>) : <div className="ops-empty"><GitMerge size={22} /><strong>No analyst mappings</strong><p>Validated source-to-ARN decisions will appear here.</p></div>}</div></section>
  </div>;
}

function Monitors({ monitors, runs, working, act }: { monitors: Monitor[]; runs: Payload["monitorRuns"]; working: string; act: (action: string, body: Record<string, unknown>, success: string) => Promise<boolean> }) {
  const [form, setForm] = useState({ name: "", query: "", groupBy: "account", schedule: "daily", triggerMode: "enters", visibility: "team", destination: "" });
  return <div className="ops-two-column"><section className="panel"><div className="panel-header"><div><h2>New evidence monitor</h2><p>Persist a query and notify when its result set changes</p></div><BellRing size={18} /></div><form className="ops-stack" onSubmit={async (event) => { event.preventDefault(); if (await act("monitor-save", { ...form, destinations: form.destination ? [form.destination] : [] }, "Evidence monitor created.")) setForm({ ...form, name: "", query: "" }); }}>
    <label>Monitor name<input required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Production public admin ports" /></label>
    <label>Advanced query<input value={form.query} onChange={(event) => setForm({ ...form, query: event.target.value })} placeholder="Production 22 critical Payments" /></label>
    <div className="ops-form-grid"><label>Group results by<select value={form.groupBy} onChange={(event) => setForm({ ...form, groupBy: event.target.value })}><option value="account">Account</option><option value="organizational-unit">Organizational unit</option><option value="environment">Environment</option><option value="region">Region</option><option value="owner">Owner</option><option value="severity">Severity</option></select></label><label>Schedule<select value={form.schedule} onChange={(event) => setForm({ ...form, schedule: event.target.value })}><option value="hourly">Hourly</option><option value="daily">Daily</option><option value="weekly">Weekly</option></select></label><label>Notify when<select value={form.triggerMode} onChange={(event) => setForm({ ...form, triggerMode: event.target.value })}><option value="enters">Finding enters view</option><option value="leaves">Finding leaves view</option><option value="severity-change">Severity changes</option><option value="coverage-gap">Coverage falls</option><option value="recurrence">Finding recurs</option></select></label><label>Visibility<select value={form.visibility} onChange={(event) => setForm({ ...form, visibility: event.target.value })}><option value="team">Team</option><option value="personal">Personal</option></select></label></div>
    <label>Destination (optional)<input value={form.destination} onChange={(event) => setForm({ ...form, destination: event.target.value })} placeholder="security-ops@example.com or webhook route" /></label>
    <button className="button button-primary" disabled={Boolean(working)}><Plus size={15} />Create monitor</button>
  </form></section><section className="panel"><div className="panel-header"><div><h2>Active monitors</h2><p>Recurring queries and latest set transitions</p></div><span className="version-chip">{monitors.length}</span></div><div className="ops-list">{monitors.length ? monitors.map((monitor) => { const run = runs.find((item) => item.monitorId === monitor.id); return <article key={monitor.id}><header><strong>{monitor.name}</strong><span className={`ops-state ${monitor.status}`}>{monitor.status}</span></header><code>{monitor.query || "All security groups"}</code><p>{monitor.schedule} · grouped by {monitor.groupBy} · notify on {monitor.triggerMode}</p><div className="ops-run-stats"><span><strong>{monitor.lastMatchCount}</strong> matches</span><span><strong>{run?.enteredCount ?? 0}</strong> entered</span><span><strong>{run?.exitedCount ?? 0}</strong> exited</span></div><footer><span>Next {when(monitor.nextRunAt)}</span><div><button onClick={() => void act("monitor-run", { id: monitor.id }, "Monitor evaluation completed.")}><Play size={13} />Run</button><button onClick={() => void act("monitor-status", { id: monitor.id, status: monitor.status === "active" ? "paused" : "active" }, `Monitor ${monitor.status === "active" ? "paused" : "activated"}.`)}>{monitor.status === "active" ? <Pause size={13} /> : <Play size={13} />}{monitor.status === "active" ? "Pause" : "Activate"}</button><button onClick={() => { if (window.confirm("Delete this monitor and stop future evaluations?")) void act("monitor-delete", { id: monitor.id }, "Monitor deleted."); }}><Trash2 size={13} /></button></div></footer></article>; }) : <div className="ops-empty"><BellRing size={22} /><strong>No recurring monitors</strong><p>Create a monitor for evidence changes that require attention.</p></div>}</div></section></div>;
}

function Exports({ jobs, parquetWorker, working, act }: { jobs: ExportJob[]; parquetWorker: boolean; working: string; act: (action: string, body: Record<string, unknown>, success: string) => Promise<boolean> }) {
  const [form, setForm] = useState({ name: "", query: "", format: "csv", schedule: "once" });
  function download(job: ExportJob) { window.location.assign(`/api/organization-operations?download=${encodeURIComponent(job.id)}`); }
  return <div className="ops-two-column"><section className="panel"><div className="panel-header"><div><h2>Create governed export</h2><p>Point-in-time or scheduled evidence packages with durable job history</p></div><Download size={18} /></div><form className="ops-stack" onSubmit={async (event) => { event.preventDefault(); if (await act("export-create", form, form.format === "parquet" || form.schedule !== "once" ? "Export queued for the AWS worker." : "Export is ready to download.")) setForm({ ...form, name: "", query: "" }); }}><label>Export name<input required value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Q3 public exposure evidence" /></label><label>Scope query<input value={form.query} onChange={(event) => setForm({ ...form, query: event.target.value })} placeholder="Production critical" /></label><div className="ops-form-grid"><label>Format<select value={form.format} onChange={(event) => setForm({ ...form, format: event.target.value })}><option value="csv">CSV</option><option value="json">JSON</option><option value="evidence-package">Auditor evidence package</option><option value="parquet">Parquet (AWS worker)</option></select></label><label>Schedule<select value={form.schedule} onChange={(event) => setForm({ ...form, schedule: event.target.value })}><option value="once">Run once</option><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option></select></label></div>{form.format === "parquet" && !parquetWorker ? <p className="ops-inline-note"><AlertTriangle size={14} />The job will remain queued until the production AWS export worker is enabled.</p> : null}<button className="button button-primary" disabled={Boolean(working)}><Plus size={15} />Create export job</button></form></section>
    <section className="panel"><div className="panel-header"><div><h2>Export jobs</h2><p>Reproducible delivery history and expiration state</p></div><span className="version-chip">{jobs.length}</span></div><div className="ops-list">{jobs.length ? jobs.map((job) => <article key={job.id}><header><strong>{job.name}</strong><span className={`ops-state ${job.status}`}>{job.status}</span></header><p>{job.format} · {job.schedule} · {job.rowCount} security groups</p><footer><span>{when(job.createdAt)} · {job.requestedBy}</span><button disabled={job.status !== "complete"} title={job.status !== "complete" ? "The background worker has not completed this export." : "Download export"} onClick={() => download(job)}><Download size={13} />Download</button></footer></article>) : <div className="ops-empty"><Download size={22} /><strong>No export jobs</strong><p>Create a scoped evidence export for analysts or auditors.</p></div>}</div></section></div>;
}

function Controls({ data, working, act }: { data: Payload; working: string; act: (action: string, body: Record<string, unknown>, success: string) => Promise<boolean> }) {
  const [retention, setRetention] = useState(data.retention);
  const active = data.riskPolicies.find((item) => item.status === "active");
  const [policyName, setPolicyName] = useState(active?.name ?? "Organization default");
  const [weights, setWeights] = useState<RiskWeights>(active?.weights ?? defaultRiskWeights);
  const [hold, setHold] = useState({ name: "", scopeType: "account", scopeValue: "", reason: "" });
  return <div className="ops-controls-grid"><section className="panel"><div className="panel-header"><div><h2>Risk scoring policy</h2><p>Versioned weights applied to normalized evidence signals</p></div><SlidersHorizontal size={18} /></div><div className="ops-stack"><label>Policy name<input value={policyName} onChange={(event) => setPolicyName(event.target.value)} /></label>{Object.entries(weights).map(([key, value]) => <label className="ops-weight" key={key}><span>{key.replace(/([A-Z])/g, " $1")}<strong>{value} pts</strong></span><input type="range" min="0" max="50" value={value} onChange={(event) => setWeights({ ...weights, [key]: Number(event.target.value) })} /></label>)}<div className="ops-button-row"><button className="button button-secondary" onClick={() => void act("risk-policy-save", { id: active?.id, name: policyName, weights }, "Risk policy draft saved.")} disabled={Boolean(working)}><Save size={15} />Save draft</button><button className="button button-primary" onClick={() => void act("risk-policy-activate", { id: active?.id, name: policyName, weights }, "Risk policy activated.")} disabled={Boolean(working)}><ShieldCheck size={15} />Activate policy</button></div></div></section>
    <section className="panel"><div className="panel-header"><div><h2>Retention policy</h2><p>Workspace metadata lifecycle; active legal holds always override deletion</p></div><Database size={18} /></div><div className="ops-form-grid">{([['rawEvidenceDays','Raw S3 evidence'],['normalizedEvidenceDays','Normalized evidence'],['auditDays','Audit trail'],['exportDays','Generated exports']] as Array<[keyof typeof retention,string]>).map(([key, label]) => <label key={key}>{label}<div className="ops-number"><input type="number" min="7" max="3650" value={retention[key]} onChange={(event) => setRetention({ ...retention, [key]: Number(event.target.value) })} /><span>days</span></div></label>)}</div><button className="button button-primary" onClick={() => void act("retention-update", retention, "Retention policy updated.")} disabled={Boolean(working)}><Save size={15} />Save retention</button></section>
    <section className="panel"><div className="panel-header"><div><h2>Legal holds</h2><p>Preserve evidence by workspace, account, security group, finding, or export</p></div><Archive size={18} /></div><form className="ops-stack" onSubmit={async (event) => { event.preventDefault(); if (await act("hold-create", hold, "Legal hold created.")) setHold({ ...hold, name: "", scopeValue: "", reason: "" }); }}><label>Hold name<input required value={hold.name} onChange={(event) => setHold({ ...hold, name: event.target.value })} placeholder="Q3 regulatory review" /></label><div className="ops-form-grid"><label>Scope<select value={hold.scopeType} onChange={(event) => setHold({ ...hold, scopeType: event.target.value })}><option value="workspace">Workspace</option><option value="account">AWS account</option><option value="security-group">Security group ARN</option><option value="finding">Finding fingerprint</option><option value="export">Export job</option></select></label><label>Scope value<input required value={hold.scopeValue} onChange={(event) => setHold({ ...hold, scopeValue: event.target.value })} placeholder="123456789012" /></label></div><label>Reason<textarea required value={hold.reason} onChange={(event) => setHold({ ...hold, reason: event.target.value })} placeholder="Matter, requestor, and preservation rationale." /></label><button className="button button-primary" disabled={Boolean(working)}><Plus size={15} />Create legal hold</button></form><div className="ops-list compact-list">{data.legalHolds.map((item) => <article key={item.id} className={item.status !== "active" ? "muted" : ""}><header><strong>{item.name}</strong><span className={`ops-state ${item.status}`}>{item.status}</span></header><p>{item.scopeType}: {item.scopeValue}</p><footer><span>{item.reason}</span>{item.status === "active" ? <button onClick={() => { if (window.confirm("Release this legal hold? Normal retention can then delete matching evidence.")) void act("hold-release", { id: item.id }, "Legal hold released."); }}><Trash2 size={13} />Release</button> : null}</footer></article>)}</div></section>
  </div>;
}
