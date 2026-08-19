"use client";

import {
  Activity, AlertTriangle, ArrowRight, BadgeCheck, Boxes, CheckCircle2,
  Clock3, CloudCog, Code2, GitPullRequest, Network, Play, RefreshCw,
  Route, ShieldAlert, ShieldCheck, Siren, Target, Users, Webhook, Zap,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  executiveNarrative, exposureSlo, graphEdges, graphNodes, operationSeeds,
  operationTransitions, type OperationKind, type OperationRecord,
} from "../lib/exposure-operations";

type Tab = "command" | "verify" | "graph" | "remediate" | "owners" | "incidents" | "policy";
type Props = { onToast: (message: string) => void };

const tabs: { id: Tab; label: string; icon: typeof Activity }[] = [
  { id: "command", label: "Command center", icon: Activity },
  { id: "verify", label: "AWS verification", icon: Route },
  { id: "graph", label: "Attack graph", icon: Network },
  { id: "remediate", label: "Remediation", icon: Target },
  { id: "owners", label: "Owner actions", icon: Users },
  { id: "incidents", label: "Incident mode", icon: Siren },
  { id: "policy", label: "Policies & API", icon: Code2 },
];

const nextStatus: Partial<Record<OperationKind, Record<string, string>>> = {
  "verification-run": { queued: "running", running: "verified", failed: "queued", inconclusive: "queued", unreachable: "queued", verified: "queued" },
  "exposure-correlation": { open: "confirmed", confirmed: "reconciled", reconciled: "open", dismissed: "open" },
  "remediation-plan": { draft: "simulated", simulated: "awaiting-approval", "awaiting-approval": "approved", approved: "executing", executing: "verifying", verifying: "completed", failed: "draft", "rolled-back": "draft", completed: "verifying" },
  "owner-action": { open: "accepted", accepted: "completed", blocked: "accepted", overdue: "accepted", completed: "open" },
  incident: { open: "investigating", investigating: "contained", contained: "resolved", resolved: "open" },
  "policy-pack": { draft: "monitor", monitor: "enforced", enforced: "monitor", disabled: "draft" },
  extension: { disabled: "enabled", enabled: "disabled", error: "disabled" },
  "evidence-gap": { open: "collecting", collecting: "resolved", resolved: "open", accepted: "open" },
};

function label(value: string) {
  return value.replaceAll("-", " ").replace(/^./, (letter) => letter.toUpperCase());
}

function payloadNumber(record: OperationRecord, key: string) {
  const value = record.payload[key];
  return typeof value === "number" ? value : 0;
}

function payloadText(record: OperationRecord, key: string) {
  const value = record.payload[key];
  return typeof value === "string" ? value : "";
}

function OperationCard({
  record,
  detail,
  saving,
  referenceMode,
  onUpdate,
}: {
  record: OperationRecord;
  detail?: React.ReactNode;
  saving: boolean;
  referenceMode?: boolean;
  onUpdate: (record: OperationRecord, status: string) => void;
}) {
  const next = nextStatus[record.kind]?.[record.status];
  const isReference = referenceMode ?? (!record.createdAt && !record.updatedAt);
  return <article className="ops-card">
    <div className="ops-card-head"><div><span className={`ops-status ops-status-${record.status}`}>{label(record.status)}</span><h3>{record.note}</h3></div><strong>{record.ticketRef || "No ticket"}</strong></div>
    <code className="ops-subject">{record.subjectId}</code>
    <div className="ops-card-meta"><span><Users size={14} />{record.owner}</span>{record.expiresAt ? <span><Clock3 size={14} />Due {record.expiresAt}</span> : null}</div>
    {detail}
    {next ? <button className="button button-primary" disabled={saving || isReference} title={isReference ? "Connect live AWS evidence before creating an operation" : undefined} onClick={() => onUpdate(record, next)}>{saving ? <RefreshCw className="spin" size={15} /> : <Play size={15} />}{label(next)}</button> : null}
  </article>;
}

export default function ExposureOperationsView({ onToast }: Props) {
  const [tab, setTab] = useState<Tab>("command");
  const [persisted, setPersisted] = useState<Record<string, OperationRecord>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState("");
  const [selectedNode, setSelectedNode] = useState("sg");

  useEffect(() => {
    let active = true;
    fetch("/api/intelligence", { cache: "no-store" })
      .then(async (response) => {
        const body = await response.json() as { records?: OperationRecord[]; error?: string };
        if (!response.ok) throw new Error(body.error ?? "Exposure operations are unavailable.");
        return body.records ?? [];
      })
      .then((records) => {
        if (!active) return;
        setPersisted(Object.fromEntries(records.map((record) => [record.id, record])));
      })
      .catch((caught) => active && setError(caught instanceof Error ? caught.message : "Exposure operations are unavailable."))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, []);

  const records = useMemo(
    () => operationSeeds.map((seed) => persisted[seed.id] ?? seed),
    [persisted],
  );
  const durableOperations = Object.values(persisted).filter((record) => record.kind in operationTransitions).length;
  const referenceMode = durableOperations === 0;
  const byKind = (kind: OperationKind) => records.filter((record) => record.kind === kind);

  async function update(record: OperationRecord, status: string) {
    if (!operationTransitions[record.kind][record.status]?.includes(status)) {
      setError(`Transition from ${record.status} to ${status} is not permitted.`);
      return;
    }
    setSaving(record.id);
    setError("");
    try {
      const saveStatus = async (input: OperationRecord, next: string) => {
        const response = await fetch("/api/intelligence", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ action: "upsert", ...input, status: next }),
        });
        const body = await response.json() as { record?: OperationRecord; error?: string };
        if (!response.ok || !body.record) throw new Error(body.error ?? "The operation could not be saved.");
        return body.record;
      };
      const current = persisted[record.id] ?? await saveStatus(record, record.status);
      const saved = await saveStatus(current, status);
      setPersisted((items) => ({ ...items, [record.id]: saved }));
      onToast(`${label(record.kind)} moved to ${label(status)}.`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The operation could not be saved.");
    } finally {
      setSaving("");
    }
  }

  const selected = graphNodes.find((node) => node.id === selectedNode) ?? graphNodes[0];
  const connected = graphEdges.filter((edge) => edge.from === selected.id || edge.to === selected.id);
  const verification = byKind("verification-run")[0];
  const correlation = byKind("exposure-correlation")[0];
  const remediation = byKind("remediation-plan")[0];
  const owner = byKind("owner-action")[0];
  const incident = byKind("incident")[0];
  const policy = byKind("policy-pack")[0];
  const extension = byKind("extension")[0];
  const gap = byKind("evidence-gap")[0];

  return <div className="exposure-operations">
    <header className="page-header"><div><p className="eyebrow">Closed-loop exposure management</p><h1>Exposure operations</h1><p>Prove reachability, correlate AWS signals, control remediation, and measure whether risk actually stays removed.</p></div><span className="read-only-pill"><ShieldCheck size={14} />{referenceMode ? "Reference scenario · connect AWS evidence" : `${durableOperations} durable operations`}</span></header>
    <nav className="ops-tabs" aria-label="Exposure operations sections">{tabs.map((item) => { const Icon = item.icon; return <button key={item.id} className={tab === item.id ? "active" : ""} onClick={() => setTab(item.id)}><Icon size={16} />{item.label}</button>; })}</nav>
    {error ? <div className="inline-error" role="alert"><AlertTriangle size={16} />{error}<button onClick={() => setError("")}>Dismiss</button></div> : null}
    {!loading && referenceMode ? <div className="ops-reference-note"><AlertTriangle size={16} /><span><strong>Reference scenario</strong> These records demonstrate the complete workflow. State-changing controls remain disabled until a live AWS finding creates a durable operation.</span></div> : null}
    {loading ? <section className="panel ops-loading"><RefreshCw className="spin" size={22} />Loading durable operations…</section> : null}

    {!loading && tab === "command" ? <>
      <section className="ops-metrics">
        <article className="ops-metric alert"><span>Critical exposure hours</span><strong>{exposureSlo.confirmedCriticalExposureHours}</strong><small>Target ≤ {exposureSlo.targetHours} hours</small></article>
        <article className="ops-metric"><span>Median validation</span><strong>{exposureSlo.medianValidationMinutes}m</strong><small>AWS-native path proof</small></article>
        <article className="ops-metric"><span>Median remediation</span><strong>{exposureSlo.medianRemediationHours}h</strong><small>Detection through verification</small></article>
        <article className="ops-metric"><span>Auto re-verified</span><strong>{exposureSlo.automaticallyReverifiedPercent}%</strong><small>{exposureSlo.reopenRatePercent}% reopen rate</small></article>
        <article className="ops-metric"><span>Evidence ready</span><strong>{exposureSlo.evidenceReadyPercent}%</strong><small>{exposureSlo.ownerSlaPercent}% owner SLA</small></article>
      </section>
      <section className="panel ops-narrative"><div><Zap size={22} /><div><p className="eyebrow">Executive narrative</p><h2>What needs attention now</h2></div></div><p>{executiveNarrative(records)}</p><div className="ops-actions"><button className="button button-primary" onClick={() => setTab("remediate")}>Open highest-value fix <ArrowRight size={15} /></button><button className="button button-secondary" onClick={() => setTab("verify")}>Collect missing proof</button></div></section>
      <section className="ops-command-grid">
        <article className="panel"><ShieldAlert size={20} /><h2>Signal convergence</h2><strong>{payloadNumber(correlation, "agreements")} sources agree</strong><p>{payloadNumber(correlation, "contradictions")} contradiction remains visible; no provider silently overrides another.</p></article>
        <article className="panel"><Target size={20} /><h2>Choke-point opportunity</h2><strong>{payloadNumber(remediation, "pathsRemoved")} paths removed</strong><p>{payloadNumber(remediation, "trafficPreserved")}% projected approved traffic preservation with rollback evidence.</p></article>
        <article className="panel"><CloudCog size={20} /><h2>Coverage gap</h2><strong>{payloadNumber(gap, "affectedFindings")} findings affected</strong><p>{payloadText(gap, "collectionAction")}</p></article>
      </section>
    </> : null}

    {!loading && tab === "verify" ? <section className="ops-two-column">
      <OperationCard record={verification} saving={saving === verification.id} onUpdate={(record, status) => void update(record, status)} detail={<div className="ops-detail-grid"><span>Analyzer<strong>{payloadText(verification, "analyzer")}</strong></span><span>Packet header<strong>{payloadText(verification, "protocol") || "TCP"}/{payloadNumber(verification, "port")}</strong></span><span>Post-change<strong>{verification.payload.automaticRerun ? "Automatic rerun" : "Manual"}</strong></span></div>} />
      <OperationCard record={correlation} saving={saving === correlation.id} onUpdate={(record, status) => void update(record, status)} detail={<div className="ops-detail-grid"><span>Traits<strong>{payloadNumber(correlation, "traits")}</strong></span><span>Agreements<strong>{payloadNumber(correlation, "agreements")}</strong></span><span>Blast radius<strong>{payloadNumber(correlation, "blastRadius")} resources</strong></span></div>} />
      <OperationCard record={gap} saving={saving === gap.id} onUpdate={(record, status) => void update(record, status)} detail={<p className="ops-callout">Gatewatch keeps this verdict evidence-incomplete until AWS collection succeeds; zero observed flows never becomes proof of safety.</p>} />
    </section> : null}

    {!loading && tab === "graph" ? <section className="ops-graph-layout">
      <article className="panel ops-graph"><div className="panel-header"><div><h2>Potential attack path</h2><p>Network, workload, identity, and data relationships</p></div><span className="ops-status ops-status-verified">3 observed edges</span></div><div className="ops-graph-track">{graphNodes.map((node, index) => <div key={node.id} className="ops-graph-step">{index ? <ArrowRight size={19} /> : null}<button className={`${node.type} ${selectedNode === node.id ? "selected" : ""}`} onClick={() => setSelectedNode(node.id)}><span>{node.label}</span><strong>{node.risk}</strong><small>{node.type}</small></button></div>)}</div><p className="ops-legend"><span />Observed traffic or attachment <span />Configured relationship</p></article>
      <aside className="panel ops-inspector"><p className="eyebrow">Selected choke point</p><h2>{selected.label}</h2><div className="risk-number">{selected.risk}<small>/100 risk</small></div><h3>Connected paths</h3>{connected.map((edge) => <p key={`${edge.from}:${edge.to}`}><BadgeCheck size={14} />{edge.label} · {edge.observed ? "observed" : "configured"}</p>)}<button className="button button-primary" onClick={() => setTab("remediate")}>Simulate change</button></aside>
    </section> : null}

    {!loading && tab === "remediate" ? <section className="ops-two-column">
      <OperationCard record={remediation} saving={saving === remediation.id} onUpdate={(record, status) => void update(record, status)} detail={<><div className="ops-mode-row"><span className={payloadText(remediation, "mode") === "advisory" ? "active" : ""}>Advisory</span><span className={payloadText(remediation, "mode") === "pull-request" ? "active" : ""}><GitPullRequest size={14} />Pull request</span><span className={payloadText(remediation, "mode") === "firewall-manager" ? "active" : ""}>Firewall Manager</span></div><div className="ops-detail-grid"><span>Paths removed<strong>{payloadNumber(remediation, "pathsRemoved")}</strong></span><span>Traffic preserved<strong>{payloadNumber(remediation, "trafficPreserved")}%</strong></span><span>Canary scope<strong>{payloadNumber(remediation, "canaryAccounts")} accounts</strong></span></div><p className="ops-callout">Four-eyes approval is enforced. Authors cannot approve their own production change; every execution enters post-change verification.</p></>} />
      <article className="panel ops-safety"><ShieldCheck size={25} /><h2>Execution safety contract</h2>{["Immutable before/after evidence", "Two-person approval", "Canary accounts before OU expansion", "Maintenance window and conflict check", "Automatic AWS path re-verification", "Rollback on lost approved traffic"].map((item) => <p key={item}><CheckCircle2 size={15} />{item}</p>)}</article>
    </section> : null}

    {!loading && tab === "owners" ? <section className="ops-two-column">
      <OperationCard record={owner} saving={saving === owner.id} onUpdate={(record, status) => void update(record, status)} detail={<div className="ops-detail-grid"><span>Open findings<strong>{payloadNumber(owner, "findings")}</strong></span><span>Critical<strong>{payloadNumber(owner, "critical")}</strong></span><span>SLA remaining<strong>{payloadNumber(owner, "slaHoursRemaining")}h</strong></span></div>} />
      <article className="panel"><Users size={23} /><h2>Owner self-service contract</h2><p>Owners see only their assigned applications, exact evidence, proposed change, due date, and governed exception route. They cannot lower severity or approve their own exception.</p><div className="ops-benchmark"><span>Payments Platform<strong>84%</strong></span><span>Cloud Operations<strong>93%</strong></span><span>Commerce Platform<strong>71%</strong></span></div></article>
    </section> : null}

    {!loading && tab === "incidents" ? <section className="ops-two-column">
      <OperationCard record={incident} saving={saving === incident.id} onUpdate={(record, status) => void update(record, status)} detail={<div className="ops-detail-grid"><span>Affected paths<strong>{payloadNumber(incident, "affectedPaths")}</strong></span><span>Lateral targets<strong>{payloadNumber(incident, "lateralTargets")}</strong></span><span>Evidence lock<strong>{incident.payload.evidencePreserved ? "Preserved" : "Pending"}</strong></span></div>} />
      <article className="panel ops-incident"><Siren size={27} /><h2>Incident mode priorities</h2><p>GuardDuty activity, confirmed ingress, privileged identity, and reachable data are treated as one incident path—not four unrelated findings.</p><ol><li>Preserve the evidence snapshot and finding graph.</li><li>Confirm current reachability and active sessions.</li><li>Identify the least disruptive containment choke point.</li><li>Re-verify containment and retain the decision timeline.</li></ol></article>
    </section> : null}

    {!loading && tab === "policy" ? <section className="ops-two-column">
      <OperationCard record={policy} saving={saving === policy.id} onUpdate={(record, status) => void update(record, status)} detail={<div className="ops-detail-grid"><span>Version<strong>v{payloadNumber(policy, "version")}</strong></span><span>Scope<strong>{payloadText(policy, "scope")}</strong></span><span>Violations<strong>{payloadNumber(policy, "violations")}</strong></span></div>} />
      <OperationCard record={extension} saving={saving === extension.id} onUpdate={(record, status) => void update(record, status)} detail={<><div className="ops-detail-grid"><span>Schema<strong>{payloadText(extension, "schemaVersion")}</strong></span><span>Authentication<strong>{payloadText(extension, "authentication")}</strong></span><span>Delivery<strong>{payloadText(extension, "lastDelivery")}</strong></span></div><p className="ops-callout"><Webhook size={15} />Extension payloads are schema-versioned, signed, workspace-bound, rate-limited, and enrichment-only.</p></>} />
      <article className="panel ops-policy-note"><Boxes size={22} /><h2>Versioned policy packs</h2><p>Start in monitor mode, inspect affected resources and exceptions, canary the enforcement scope, then promote through an administrator-controlled transition. Existing Firewall Manager-managed groups remain explicitly tagged to avoid competing controllers.</p></article>
    </section> : null}
  </div>;
}
