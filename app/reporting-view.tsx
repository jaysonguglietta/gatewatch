"use client";

import {
  AlertTriangle,
  Building2,
  CircleCheck,
  Download,
  FileBarChart,
  Globe2,
  Link2,
  Network,
  RefreshCw,
  Server,
  ShieldAlert,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

type Count = { label: string; count: number };
type Report = {
  generatedAt: string;
  snapshot: { generatedAt: string; complete: boolean; errorCount: number };
  summary: Record<string, number>;
  severity: Count[];
  workflow: Count[];
  byAccount: Array<{ accountId: string; accountName: string; groups: number; findings: number; critical: number; publicIngress: number; publicEgress: number; attachments: number; maxRisk: number }>;
  byRegion: Array<{ region: string; groups: number; findings: number; publicRules: number; maxRisk: number }>;
  resourceTypes: Count[];
  topFindings: Array<{ fingerprint: string; title: string; securityGroupName: string; accountName: string; region: string; severity: string; riskScore: number; status: string; jiraIssueKey: string }>;
};

function dateTime(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(parsed);
}

function Bars({ values }: { values: Count[] }) {
  const maximum = Math.max(1, ...values.map((item) => item.count));
  return <div className="report-bars">{values.map((item) => <div key={item.label}><span><strong>{item.label.replaceAll("-", " ")}</strong><em>{item.count}</em></span><div><i style={{ width: `${(item.count / maximum) * 100}%` }} /></div></div>)}</div>;
}

export default function ReportingView({ onToast }: { onToast: (message: string) => void }) {
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/reports", { cache: "no-store" });
      const payload = (await response.json()) as Report & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Report could not be generated.");
      setReport(payload);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Report could not be generated.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { const timer = window.setTimeout(() => void load(), 0); return () => window.clearTimeout(timer); }, []);

  async function download() {
    try {
      const response = await fetch("/api/reports?format=csv");
      if (!response.ok) throw new Error("Export failed.");
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `gatewatch-detailed-report-${new Date().toISOString().slice(0, 10)}.csv`;
      link.click();
      URL.revokeObjectURL(url);
      onToast("Detailed evidence report exported.");
    } catch (caught) {
      onToast(caught instanceof Error ? caught.message : "Export failed.");
    }
  }

  async function downloadEvidencePackage() {
    try {
      const response = await fetch("/api/evidence-packages");
      if (!response.ok) throw new Error("Evidence package export failed.");
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url;
      link.download = `gatewatch-auditor-evidence-${new Date().toISOString().slice(0, 10)}.json`;
      link.click();
      URL.revokeObjectURL(url);
      onToast("Auditor evidence package exported.");
    } catch (caught) {
      onToast(caught instanceof Error ? caught.message : "Evidence package export failed.");
    }
  }

  const maximumRegionFindings = useMemo(() => Math.max(1, ...(report?.byRegion.map((item) => item.findings) ?? [1])), [report]);

  return <>
    <div className="page-header">
      <div><p className="eyebrow">Point-in-time evidence report</p><h1>Detailed reporting</h1><p>Current exposure, workload attachment, workflow, account, region, and Jira coverage from the latest AWS snapshot.</p></div>
      <div className="page-actions"><button className="button button-secondary" onClick={() => void load()} disabled={loading}><RefreshCw size={15} className={loading ? "spin" : ""} />Refresh</button><button className="button button-secondary" onClick={() => void downloadEvidencePackage()} disabled={!report}><FileBarChart size={15} />Auditor package</button><button className="button button-primary" onClick={() => void download()} disabled={!report}><Download size={15} />Export detailed CSV</button></div>
    </div>
    {error ? <div className="daily-error" role="alert"><AlertTriangle size={17} /><p><strong>Report unavailable</strong><span>{error}</span></p><button onClick={() => void load()}>Try again</button></div> : null}
    {loading && !report ? <section className="panel report-loading"><RefreshCw className="spin" size={20} /><strong>Aggregating current AWS evidence…</strong></section> : null}
    {report ? <>
      <section className={`report-freshness ${report.snapshot.complete ? "complete" : "partial"}`}><CircleCheck size={18} /><div><strong>{report.snapshot.complete ? "Complete AWS snapshot" : "Partial AWS snapshot"}</strong><p>Evidence collected {dateTime(report.snapshot.generatedAt)} · Report generated {dateTime(report.generatedAt)}</p></div><span>{report.snapshot.errorCount} collection errors</span></section>
      <section className="report-scorecards">
        {([
          ["Findings", report.summary.findings, `${report.summary.critical} critical · ${report.summary.high} high`, ShieldAlert],
          ["Public ingress", report.summary.publicIngressRules, "Internet-wide inbound rules", Globe2],
          ["Public egress", report.summary.publicEgressRules, "Internet-wide outbound rules", Network],
          ["Attached resources", report.summary.attachedResources, `${report.summary.securityGroups} security groups`, Server],
          ["Awaiting action", report.summary.awaitingAction, `${report.summary.overdue} overdue follow-ups`, AlertTriangle],
          ["Jira coverage", report.summary.jiraLinked, `${report.summary.acceptedRisk} accepted-risk findings`, Link2],
        ] as Array<[string, number, string, LucideIcon]>).map(([label, value, helper, Icon]) => <article className="panel" key={label}><span><Icon size={17} /></span><p><small>{label}</small><strong>{value.toLocaleString()}</strong><em>{helper}</em></p></article>)}
      </section>
      <div className="report-grid">
        <section className="panel report-breakdown"><div className="panel-header"><div><h2>Severity distribution</h2><p>Prioritized findings in the current snapshot</p></div></div><Bars values={report.severity} /></section>
        <section className="panel report-breakdown"><div className="panel-header"><div><h2>Workflow disposition</h2><p>Daily review and exception state</p></div></div><Bars values={report.workflow} /></section>
        <section className="panel report-breakdown"><div className="panel-header"><div><h2>Attached resource types</h2><p>Resolved parent workloads and managed services</p></div></div>{report.resourceTypes.length ? <Bars values={report.resourceTypes} /> : <div className="report-empty"><Server size={20} />No attached resources were resolved.</div>}</section>
      </div>
      <section className="panel report-table-panel"><div className="panel-header"><div><h2>Account posture</h2><p>Exposure and workflow concentration by AWS account</p></div><span className="version-chip">{report.byAccount.length} accounts</span></div><div className="table-wrap"><table><thead><tr><th>Account</th><th>Groups</th><th>Findings</th><th>Critical</th><th>Public ingress</th><th>Public egress</th><th>Resources</th><th>Max risk</th></tr></thead><tbody>{report.byAccount.map((item) => <tr key={item.accountId}><td><strong>{item.accountName}</strong><small>{item.accountId}</small></td><td>{item.groups}</td><td>{item.findings}</td><td>{item.critical}</td><td>{item.publicIngress}</td><td>{item.publicEgress}</td><td>{item.attachments}</td><td><span className={`compact-risk risk-${item.maxRisk >= 85 ? "critical" : item.maxRisk >= 70 ? "high" : item.maxRisk >= 45 ? "medium" : "low"}`}>{item.maxRisk}</span></td></tr>)}</tbody></table></div></section>
      <div className="report-lower-grid">
        <section className="panel"><div className="panel-header"><div><h2>Regional concentration</h2><p>Findings and public rules by region</p></div><Building2 size={18} /></div><div className="region-report-list">{report.byRegion.map((item) => <article key={item.region}><div><strong>{item.region}</strong><span>{item.groups} groups · {item.publicRules} public rules</span></div><div className="region-report-track"><i style={{ width: `${(item.findings / maximumRegionFindings) * 100}%` }} /></div><em>{item.findings} findings · risk {item.maxRisk}</em></article>)}</div></section>
        <section className="panel report-top-findings"><div className="panel-header"><div><h2>Highest-risk findings</h2><p>Current priorities and Jira coverage</p></div><FileBarChart size={18} /></div>{report.topFindings.map((item) => <article key={item.fingerprint}><span className={`compact-risk risk-${item.severity}`}>{item.riskScore}</span><p><strong>{item.title}</strong><small>{item.securityGroupName} · {item.accountName} · {item.region}</small></p>{item.jiraIssueKey ? <em><Link2 size={11} />{item.jiraIssueKey}</em> : <em>No Jira ticket</em>}</article>)}</section>
      </div>
    </> : null}
  </>;
}
