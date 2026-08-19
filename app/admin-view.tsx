"use client";

import {
  Activity,
  AlertTriangle,
  Archive,
  ArrowRight,
  BadgeCheck,
  BellRing,
  BrainCircuit,
  Check,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  CloudCog,
  Copy,
  Database,
  Download,
  ExternalLink,
  FileClock,
  FileJson2,
  Gauge,
  KeyRound,
  LockKeyhole,
  Pause,
  Play,
  PlugZap,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  Settings,
  ShieldCheck,
  Trash2,
  TicketCheck,
  UserCog,
  X,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import {
  defaultConfigResourceTypes,
  generateExternalId,
  isConfigSource,
  sourceAccessCloudFormation,
  sourceTypeDefinition,
  sourceTypeDefinitions,
  type ConnectionTestSummary,
  type IngestionSource,
  type SourceProvider,
  type SourceType,
} from "../lib/admin-sources";
import type { AdxPreview } from "../lib/azure-data-explorer";
import type { JiraStatus } from "../lib/jira-bridge";

type AdminTab =
  | "overview"
  | "sources"
  | "runs"
  | "integrations"
  | "access"
  | "retention"
  | "audit";

type Run = {
  id: string;
  sourceId: string;
  sourceName?: string;
  runType: string;
  status: string;
  discoveredObjects: number;
  processedObjects: number;
  failedObjects: number;
  parsedRecords: number;
  findingChanges: number;
  errorSummary: string;
  requestedBy: string;
  startedAt: string;
  completedAt: string;
};

type AuditEvent = {
  id: string;
  actor: string;
  action: string;
  targetType: string;
  targetId: string;
  summary: string;
  createdAt: string;
};

type Role = {
  email: string;
  role: string;
  createdBy: string;
  updatedAt: string;
};

type ObjectStat = {
  status: string;
  count: number;
  totalBytes: number;
};

type AdminPayload = {
  currentUser: { email: string; role: string };
  sources: IngestionSource[];
  runs: Run[];
  audits: AuditEvent[];
  roles: Role[];
  objectStats: ObjectStat[];
  architecture: Record<string, string>;
  settings: {
    retention?: { eventDays: number; evidenceDays: number; auditDays: number };
    notifications?: NotificationSettings;
  };
};

type NotificationSettings = {
  enabled: boolean;
  minimumSeverity: "critical" | "high" | "medium" | "low";
  events: string[];
  recipients: string[];
  digest: "immediate" | "daily";
};

type AiAnalystStatus = {
  status: {
    enabled: boolean;
    modelId: string;
    region: string;
    guardrailConfigured: boolean;
    guardrailVersion: string;
  };
  usage: {
    personal: { requests: number; inputTokens: number; outputTokens: number };
    workspaceRequests: number;
  };
  limits: { personal: number; workspace: number };
  promptVersion: string;
  schemaVersion: string;
};

type SourceDraft = {
  name: string;
  provider: SourceProvider;
  sourceType: SourceType;
  bucketArn: string;
  region: string;
  objectPrefix: string;
  roleArn: string;
  externalId: string;
  kmsKeyArn: string;
  organizationId: string;
  ingestionMode: "continuous" | "backfill" | "both";
  backfillStart: string;
  includedAccounts: string;
  excludedAccounts: string;
  includedRegions: string;
  configResourceTypes: string[];
  adxClusterUrl: string;
  adxDatabase: string;
  adxTable: string;
  adxTimestampColumn: string;
  adxPayloadColumn: string;
  adxQueryMode: "whole-row" | "payload-column";
  adxBatchSize: number;
  adxTenantId: string;
  adxClientId: string;
  adxClientSecret: string;
  adxCursorValue: string;
  retentionDays: number;
};

const emptyDraft = (): SourceDraft => ({
  name: "",
  provider: "aws-s3",
  sourceType: "cloudtrail",
  bucketArn: "",
  region: "us-east-1",
  objectPrefix: "AWSLogs/",
  roleArn: "",
  externalId: generateExternalId(),
  kmsKeyArn: "",
  organizationId: "",
  ingestionMode: "both",
  backfillStart: new Date(Date.now() - 30 * 86_400_000)
    .toISOString()
    .slice(0, 10),
  includedAccounts: "",
  excludedAccounts: "",
  includedRegions: "",
  configResourceTypes: defaultConfigResourceTypes,
  adxClusterUrl: "",
  adxDatabase: "",
  adxTable: "",
  adxTimestampColumn: "TimeGenerated",
  adxPayloadColumn: "",
  adxQueryMode: "whole-row",
  adxBatchSize: 500,
  adxTenantId: "",
  adxClientId: "",
  adxClientSecret: "",
  adxCursorValue: "",
  retentionDays: 365,
});

const statusLabels: Record<string, string> = {
  draft: "Verification pending",
  testing: "Testing",
  ready: "Ready",
  backfilling: "Backfilling",
  live: "Live",
  degraded: "Degraded",
  paused: "Paused",
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
};

function formatDate(value?: string) {
  if (!value) return "Not yet";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat("en", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

function formatBytes(value: number) {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(
    units.length - 1,
    Math.floor(Math.log(value) / Math.log(1024)),
  );
  return `${(value / 1024 ** exponent).toFixed(exponent ? 1 : 0)} ${units[exponent]}`;
}

function download(filename: string, content: string) {
  const url = URL.createObjectURL(
    new Blob([content], { type: "text/yaml;charset=utf-8" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export default function AdminView({
  onToast,
}: {
  onToast: (message: string) => void;
}) {
  const [tab, setTab] = useState<AdminTab>("overview");
  const [data, setData] = useState<AdminPayload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [wizardOpen, setWizardOpen] = useState(false);
  const [editingId, setEditingId] = useState("");
  const [draft, setDraft] = useState<SourceDraft>(emptyDraft);
  const [wizardStep, setWizardStep] = useState(1);
  const [saving, setSaving] = useState(false);
  const [busyId, setBusyId] = useState("");
  const [selectedSource, setSelectedSource] =
    useState<IngestionSource | null>(null);
  const [adxPreview, setAdxPreview] = useState<AdxPreview | null>(null);
  const [roleEmail, setRoleEmail] = useState("");
  const [roleName, setRoleName] = useState("analyst");
  const [retention, setRetention] = useState({
    eventDays: 365,
    evidenceDays: 730,
    auditDays: 2555,
  });
  const [jira, setJira] = useState<JiraStatus | null>(null);
  const [jiraError, setJiraError] = useState("");
  const [aiAnalyst, setAiAnalyst] = useState<AiAnalystStatus | null>(null);
  const [aiAnalystError, setAiAnalystError] = useState("");
  const [jiraDraft, setJiraDraft] = useState({
    baseUrl: "",
    email: "",
    apiToken: "",
    projectKey: "",
    issueType: "Task",
  });
  const [notifications, setNotifications] = useState<NotificationSettings>({
    enabled: false,
    minimumSeverity: "high",
    events: ["remediation.created", "remediation.verification-failed"],
    recipients: [],
    digest: "immediate",
  });
  const [notificationRecipients, setNotificationRecipients] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const response = await fetch("/api/admin/sources", {
        headers: { accept: "application/json" },
      });
      const payload = (await response.json()) as AdminPayload & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Admin data could not be loaded.");
      setData(payload);
      if (payload.settings?.retention) setRetention(payload.settings.retention);
      if (payload.settings?.notifications) {
        setNotifications(payload.settings.notifications);
        setNotificationRecipients(payload.settings.notifications.recipients.join(", "));
      }
    } catch (caught) {
      setError(
        caught instanceof Error
          ? caught.message
          : "Admin data could not be loaded.",
      );
    } finally {
      setLoading(false);
    }
  }

  async function loadJira() {
    try {
      const response = await fetch("/api/admin/jira", { cache: "no-store" });
      const payload = (await response.json()) as JiraStatus & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Jira status is unavailable.");
      setJira(payload);
      setJiraDraft((current) => ({
        ...current,
        baseUrl: payload.baseUrl,
        email: payload.email,
        projectKey: payload.projectKey,
        issueType: payload.issueType || "Task",
        apiToken: "",
      }));
      setJiraError("");
    } catch (caught) {
      setJiraError(caught instanceof Error ? caught.message : "Jira status is unavailable.");
    }
  }

  async function loadAiAnalyst() {
    try {
      const response = await fetch("/api/ai/analysis", { cache: "no-store" });
      const payload = (await response.json()) as AiAnalystStatus & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Bedrock analyst status is unavailable.");
      setAiAnalyst(payload);
      setAiAnalystError("");
    } catch (caught) {
      setAiAnalystError(caught instanceof Error ? caught.message : "Bedrock analyst status is unavailable.");
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void load();
      void loadJira();
      void loadAiAnalyst();
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  async function jiraAction(action: "test" | "save") {
    setSaving(true);
    setJiraError("");
    try {
      const response = await fetch("/api/admin/jira", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action, ...jiraDraft }),
      });
      const payload = (await response.json()) as JiraStatus & { error?: string };
      if (!response.ok) throw new Error(payload.error ?? "Jira configuration failed.");
      setJira(payload);
      setJiraDraft((current) => ({
        ...current,
        apiToken: action === "save" ? "" : current.apiToken,
        issueType: payload.issueType,
      }));
      onToast(action === "test" ? "Jira Cloud connection verified." : "Jira integration saved securely in AWS Secrets Manager.");
      await load();
    } catch (caught) {
      setJiraError(caught instanceof Error ? caught.message : "Jira configuration failed.");
    } finally {
      setSaving(false);
    }
  }

  async function sourceAction(
    action: string,
    source: IngestionSource,
    confirmation?: string,
  ) {
    if (confirmation && !window.confirm(confirmation)) return;
    setBusyId(source.id);
    setError("");
    try {
      const response = await fetch("/api/admin/sources", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ action, id: source.id }),
      });
      const payload = (await response.json()) as {
        source?: IngestionSource;
        test?: ConnectionTestSummary;
        preview?: AdxPreview;
        outcome?: { normalized: number; fetched: number; skipped: number };
        template?: string;
        filename?: string;
        error?: string;
      };
      if (!response.ok) throw new Error(payload.error ?? "The action failed.");
      if (action === "template" && payload.template) {
        download(payload.filename ?? "gatewatch-read-role.yaml", payload.template);
        onToast("Downloaded the least-privilege IAM role template.");
      } else if (action === "preview" && payload.preview) {
        setAdxPreview(payload.preview);
        onToast(`Queried ${payload.preview.rowCount} bounded row(s); ${payload.preview.records.length} mapped successfully.`);
      } else {
        if (payload.source) setSelectedSource(payload.source);
        await load();
        onToast(
          action === "test"
            ? payload.test?.passed
              ? "Live source connection verified."
              : "Configuration saved. Runtime verification is still pending."
            : action === "sync" || (action === "backfill" && source.provider === "azure-data-explorer")
              ? `Imported ${payload.outcome?.normalized ?? 0} normalized records from ${payload.outcome?.fetched ?? 0} ADX rows.`
            : `Source ${action} completed.`,
        );
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The action failed.");
    } finally {
      setBusyId("");
    }
  }

  async function createSource() {
    setSaving(true);
    setError("");
    try {
      const { adxClientSecret, ...source } = draft;
      const response = await fetch("/api/admin/sources", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          action: editingId ? "update" : "create",
          id: editingId || undefined,
          clientSecret: adxClientSecret,
          source: {
            ...source,
            includedAccounts: draft.includedAccounts,
            excludedAccounts: draft.excludedAccounts,
            includedRegions: draft.includedRegions,
          },
        }),
      });
      const payload = (await response.json()) as {
        source?: IngestionSource;
        error?: string;
      };
      if (!response.ok || !payload.source) {
        throw new Error(payload.error ?? "The source could not be saved.");
      }
      setWizardOpen(false);
      setEditingId("");
      setWizardStep(1);
      setDraft(emptyDraft());
      setSelectedSource(payload.source);
      setAdxPreview(null);
      await load();
      onToast(
        editingId
          ? "Data source updated. Live verification is required again."
          : "Data source saved as a draft. Run the connection test next.",
      );
    } catch (caught) {
      setError(
        caught instanceof Error ? caught.message : "The source could not be saved.",
      );
    } finally {
      setSaving(false);
    }
  }

  async function settingAction(payload: Record<string, unknown>) {
    setSaving(true);
    setError("");
    try {
      const response = await fetch("/api/admin/settings", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = (await response.json()) as { error?: string };
      if (!response.ok) throw new Error(result.error ?? "The setting could not be saved.");
      setRoleEmail("");
      await load();
      onToast("Administration settings saved and audited.");
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The setting could not be saved.");
    } finally {
      setSaving(false);
    }
  }

  async function syncJiraIssues() {
    setSaving(true);
    setJiraError("");
    try {
      const response = await fetch("/api/jira/sync", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      const payload = (await response.json()) as {
        synced?: number;
        failed?: number;
        error?: string;
      };
      if (!response.ok) throw new Error(payload.error ?? "Jira synchronization failed.");
      onToast(`Synchronized ${payload.synced ?? 0} Jira issues${payload.failed ? `; ${payload.failed} need retry` : ""}.`);
    } catch (caught) {
      setJiraError(caught instanceof Error ? caught.message : "Jira synchronization failed.");
    } finally {
      setSaving(false);
    }
  }

  const sourceTotals = useMemo(() => {
    const sources = data?.sources ?? [];
    return {
      total: sources.length,
      live: sources.filter((source) => source.status === "live").length,
      attention: sources.filter((source) =>
        ["degraded", "draft"].includes(source.status),
      ).length,
      accounts: new Set(sources.flatMap((source) => source.includedAccounts))
        .size,
    };
  }, [data]);

  const tabs: Array<[AdminTab, string, typeof Settings]> = [
    ["overview", "Overview", Gauge],
    ["sources", "Data sources", CloudCog],
    ["runs", "Ingestion runs", Activity],
    ["integrations", "Integrations", PlugZap],
    ["access", "Access & roles", UserCog],
    ["retention", "Retention", Archive],
    ["audit", "Audit log", FileClock],
  ];

  return (
    <>
      <div className="page-header">
        <div>
          <p className="eyebrow">Administration</p>
          <h1>Configuration</h1>
          <p>
            Connect AWS evidence from S3 or Azure Data Explorer, control ingestion,
            and govern who can operate Gatewatch.
          </p>
        </div>
        <div className="page-actions">
          <button className="button button-secondary" onClick={() => void load()}>
            <RefreshCw size={16} className={loading ? "spin" : ""} />
            Refresh
          </button>
          <button
            className="button button-primary"
            onClick={() => {
              setDraft(emptyDraft());
              setEditingId("");
              setWizardStep(1);
              setWizardOpen(true);
            }}
          >
            <Plus size={16} /> Add log source
          </button>
        </div>
      </div>

      <section className="admin-notice">
        <ShieldCheck size={20} />
        <div>
          <strong>Read-only by design</strong>
          <p>
            Gatewatch uses temporary AWS roles or a database-viewer Entra application.
            Raw logs remain in the source system and every administrative action is recorded.
          </p>
        </div>
        <span>Multi-source ingestion</span>
      </section>

      <div className="admin-tabs" role="tablist" aria-label="Administration sections">
        {tabs.map(([value, label, Icon]) => (
          <button
            key={value}
            role="tab"
            aria-selected={tab === value}
            className={tab === value ? "active" : ""}
            onClick={() => setTab(value)}
          >
            <Icon size={15} /> {label}
          </button>
        ))}
      </div>

      {error ? (
        <div className="admin-error" role="alert">
          <CircleAlert size={17} />
          <span>{error}</span>
          <button aria-label="Dismiss error" onClick={() => setError("")}>
            <X size={15} />
          </button>
        </div>
      ) : null}

      {loading && !data ? (
        <section className="panel admin-loading" aria-live="polite">
          <RefreshCw size={20} className="spin" />
          <strong>Loading administration data…</strong>
        </section>
      ) : null}

      {data && tab === "overview" ? (
        <div className="admin-overview">
          <section className="admin-metrics">
            {([
              ["Configured sources", sourceTotals.total, `${sourceTotals.live} live`, Database],
              ["Need attention", sourceTotals.attention, "Draft or degraded", AlertTriangle],
              ["Covered accounts", sourceTotals.accounts, "Explicit account scope", ShieldCheck],
              [
                "Processed objects",
                data.objectStats.reduce((sum, stat) => sum + Number(stat.count), 0),
                formatBytes(data.objectStats.reduce((sum, stat) => sum + Number(stat.totalBytes), 0)),
                FileJson2,
              ],
            ] as Array<[string, string | number, string, LucideIcon]>).map(([label, value, helper, Icon]) => (
              <article className="panel admin-metric" key={String(label)}>
                <span><Icon size={17} /></span>
                <p>{label}</p>
                <strong>{String(value)}</strong>
                <small>{String(helper)}</small>
              </article>
            ))}
          </section>
          <div className="admin-overview-grid">
            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>Ingestion readiness</h2>
                  <p>From immutable AWS evidence to reviewable findings</p>
                </div>
                <span className="version-chip">AWS target</span>
              </div>
              <div className="pipeline-map">
                {([
                  ["Raw evidence", "S3 or ADX", Database],
                  ["Source cursor", "Events or checkpoint", Activity],
                  ["Normalize", "Lambda workers", RefreshCw],
                  ["Query state", "Aurora PostgreSQL", Search],
                ] as Array<[string, string, LucideIcon]>).map(([label, detail, Icon], index) => (
                  <div key={String(label)}>
                    <span><Icon size={16} /></span>
                    <p><strong>{label}</strong><small>{detail}</small></p>
                    {index < 3 ? <ChevronRight size={14} /> : null}
                  </div>
                ))}
              </div>
            </section>
            <section className="panel admin-next-action">
              <span><CloudCog size={20} /></span>
              <div>
                <h2>{sourceTotals.total ? "Verify configured sources" : "Connect your first evidence source"}</h2>
                <p>
                  {sourceTotals.total
                    ? "A source must pass a live, bounded read-only connection test before activation."
                    : "Add S3 prefixes or ADX tables containing AWS configuration, reachability, traffic, access, and threat evidence."}
                </p>
                <button className="button button-dark" onClick={() => setTab("sources")}>
                  Open data sources <ArrowRight size={15} />
                </button>
              </div>
            </section>
          </div>
          <section className="panel admin-guardrails">
            <div className="panel-header">
              <div>
                <h2>Production guardrails</h2>
                <p>Controls already represented in the implementation and AWS templates</p>
              </div>
            </div>
            <div>
              {[
                ["No long-lived AWS keys", "STS role assumption with a unique external ID"],
                ["Duplicate-safe ingestion", "Object identity ledger and event-level idempotency"],
                ["Failure isolation", "Bounded parsing, quarantine state, SQS retry, and DLQ"],
                ["Evidence lineage", "Source bucket, object key, version, checksum, and event ID"],
                ["Least privilege", "Prefix-scoped S3 read and optional key-scoped KMS decrypt"],
                ["Admin accountability", "Role-restricted actions and durable audit history"],
              ].map(([title, detail]) => (
                <article key={title}>
                  <CircleCheck size={15} />
                  <p><strong>{title}</strong><span>{detail}</span></p>
                </article>
              ))}
            </div>
          </section>
        </div>
      ) : null}

      {data && tab === "sources" ? (
        <section className="panel admin-source-panel">
          <div className="panel-header">
            <div>
              <h2>Evidence sources</h2>
              <p>AWS logs from S3 or Azure Data Explorer, normalized into one evidence model</p>
            </div>
            <span className="version-chip">{data.sources.length} configured</span>
          </div>
          {data.sources.length ? (
            <div className="admin-source-list">
              {data.sources.map((source) => (
                <article
                  className={`admin-source-card ${selectedSource?.id === source.id ? "selected" : ""}`}
                  key={source.id}
                >
                  <button
                    className="admin-source-main"
                    onClick={() => { setSelectedSource(source); setAdxPreview(null); }}
                  >
                    <span className="source-icon">
                      {source.sourceType === "cloudtrail" ? <Activity size={18} /> : <Database size={18} />}
                    </span>
                    <div>
                      <strong>{source.name}</strong>
                      <p>{source.provider === "azure-data-explorer" ? `${source.adxDatabase}.${source.adxTable}` : `${source.bucketName}/${source.objectPrefix}`}</p>
                      <small>{source.provider === "azure-data-explorer" ? "Azure Data Explorer" : source.region} · {sourceTypeDefinition(source.sourceType).label}</small>
                    </div>
                    <span className={`admin-status status-${source.status}`}>
                      <i /> {statusLabels[source.status] ?? source.status}
                    </span>
                  </button>
                  <div className="admin-source-facts">
                    <span><strong>Mode</strong>{source.ingestionMode}</span>
                    <span><strong>Last test</strong>{formatDate(source.lastTestedAt)}</span>
                    <span><strong>{source.provider === "azure-data-explorer" ? "Checkpoint" : "Last object"}</strong>{formatDate(source.lastSuccessfulObjectAt)}</span>
                    <span><strong>Retention</strong>{source.retentionDays} days</span>
                  </div>
                  {selectedSource?.id === source.id ? (
                    <div className="admin-source-detail">
                      {source.provider === "azure-data-explorer" ? (
                        <div className="connection-details">
                          <span><strong>Cluster</strong><code>{source.adxClusterUrl}</code></span>
                          <span><strong>Database / table</strong><code>{source.adxDatabase}.{source.adxTable}</code></span>
                          <span><strong>Entra application</strong><code>{source.adxClientId}</code></span>
                          <span><strong>Checkpoint column</strong><code>{source.adxTimestampColumn}</code></span>
                        </div>
                      ) : (
                        <div className="connection-details">
                          <span><strong>Role ARN</strong><code>{source.roleArn}</code></span>
                          <span><strong>External ID</strong><code>{source.externalId}</code></span>
                          <span><strong>KMS key</strong><code>{source.kmsKeyArn || "Bucket-default encryption"}</code></span>
                        </div>
                      )}
                      {source.testSummary?.checks?.length ? (
                        <div className="connection-checks">
                          {source.testSummary.checks.map((item) => (
                            <div key={item.key}>
                              {item.status === "passed" ? <CircleCheck size={15} /> : item.status === "failed" ? <CircleAlert size={15} /> : <FileClock size={15} />}
                              <p><strong>{item.label}</strong><span>{item.detail}</span></p>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="empty-checks">
                          <FileClock size={17} />
                          {source.provider === "azure-data-explorer"
                            ? "Run a connection test to validate Entra authentication, database viewer access, table access, and row mapping."
                            : "Run a connection test to validate role assumption, prefix listing, and sample-object access."}
                        </div>
                      )}
                      {source.provider === "azure-data-explorer" && adxPreview ? (
                        <div className="adx-preview" aria-live="polite">
                          <div><strong>Bounded preview</strong><span>{adxPreview.records.length} mapped · {adxPreview.skippedRows} skipped · {adxPreview.columns.length} columns</span></div>
                          <pre>{adxPreview.records.map((record) => JSON.stringify(record)).join("\n") || "The table returned no rows."}</pre>
                        </div>
                      ) : null}
                      <div className="admin-source-actions">
                        <button
                          className="button button-primary"
                          disabled={busyId === source.id}
                          onClick={() => void sourceAction("test", source)}
                        >
                          <RefreshCw size={15} className={busyId === source.id ? "spin" : ""} />
                          Test connection
                        </button>
                        {source.provider === "aws-s3" ? (
                          <button className="button button-secondary" onClick={() => void sourceAction("template", source)}>
                            <Download size={15} /> IAM template
                          </button>
                        ) : (
                          <button className="button button-secondary" disabled={busyId === source.id} onClick={() => void sourceAction("preview", source)}>
                            <Search size={15} /> Preview rows
                          </button>
                        )}
                        <button
                          className="button button-secondary"
                          onClick={() => {
                            setDraft({
                              name: source.name,
                              provider: source.provider,
                              sourceType: source.sourceType,
                              bucketArn: source.bucketArn,
                              region: source.region,
                              objectPrefix: source.objectPrefix,
                              roleArn: source.roleArn,
                              externalId: source.externalId,
                              kmsKeyArn: source.kmsKeyArn,
                              organizationId: source.organizationId,
                              ingestionMode: source.ingestionMode,
                              backfillStart: source.backfillStart,
                              includedAccounts: source.includedAccounts.join(", "),
                              excludedAccounts: source.excludedAccounts.join(", "),
                              includedRegions: source.includedRegions.join(", "),
                              configResourceTypes: source.configResourceTypes,
                              adxClusterUrl: source.adxClusterUrl,
                              adxDatabase: source.adxDatabase,
                              adxTable: source.adxTable,
                              adxTimestampColumn: source.adxTimestampColumn,
                              adxPayloadColumn: source.adxPayloadColumn,
                              adxQueryMode: source.adxQueryMode,
                              adxBatchSize: source.adxBatchSize,
                              adxTenantId: source.adxTenantId,
                              adxClientId: source.adxClientId,
                              adxClientSecret: "",
                              adxCursorValue: source.adxCursorValue,
                              retentionDays: source.retentionDays,
                            });
                            setEditingId(source.id);
                            setWizardStep(1);
                            setWizardOpen(true);
                          }}
                        >
                          <Settings size={15} /> Edit
                        </button>
                        {source.status === "live" ? (
                          <button className="button button-secondary" onClick={() => void sourceAction("pause", source)}>
                            <Pause size={15} /> Pause
                          </button>
                        ) : (
                          <button
                            className="button button-secondary"
                            disabled={!source.testSummary?.passed}
                            title={!source.testSummary?.passed ? "A live connection test is required" : ""}
                            onClick={() => void sourceAction("activate", source)}
                          >
                            <Play size={15} /> Activate
                          </button>
                        )}
                        <button
                          className="button button-secondary"
                          disabled={!source.testSummary?.passed || (source.provider === "azure-data-explorer" && source.status !== "live")}
                          onClick={() => void sourceAction(source.provider === "azure-data-explorer" ? "sync" : "backfill", source)}
                        >
                          <RotateCcw size={15} /> {source.provider === "azure-data-explorer" ? "Sync now" : "Start backfill"}
                        </button>
                        <button
                          className="button button-danger"
                          disabled={["live", "backfilling"].includes(source.status)}
                          onClick={() =>
                            void sourceAction(
                              "delete",
                              source,
                              `Delete ${source.name}? This removes only the Gatewatch configuration and stored credential reference. It never deletes source logs.`,
                            )
                          }
                        >
                          <Trash2 size={15} /> Delete
                        </button>
                      </div>
                    </div>
                  ) : null}
                </article>
              ))}
            </div>
          ) : (
            <div className="admin-empty">
              <span><CloudCog size={24} /></span>
              <h3>No evidence sources yet</h3>
              <p>Connect an S3 prefix or an Azure Data Explorer table containing CloudTrail, Config, flow, access, analysis, or managed-finding records.</p>
              <button
                className="button button-primary"
                onClick={() => {
                  setDraft(emptyDraft());
                  setEditingId("");
                  setWizardStep(1);
                  setWizardOpen(true);
                }}
              >
                <Plus size={15} /> Add log source
              </button>
            </div>
          )}
        </section>
      ) : null}

      {data && tab === "runs" ? (
        <section className="panel admin-table-panel">
          <div className="panel-header">
            <div>
              <h2>Ingestion runs</h2>
              <p>Continuous deliveries, historical backfills, retries, and failures</p>
            </div>
            <span className="version-chip">Last 50</span>
          </div>
          {data.runs.length ? (
            <div className="admin-table-wrap">
              <table>
                <thead><tr><th>Source</th><th>Type</th><th>Status</th><th>Objects</th><th>Records</th><th>Findings</th><th>Started</th></tr></thead>
                <tbody>
                  {data.runs.map((run) => (
                    <tr key={run.id}>
                      <td><strong>{run.sourceName ?? run.sourceId}</strong><small>{run.id}</small></td>
                      <td>{run.runType}</td>
                      <td><span className={`admin-status status-${run.status}`}><i />{statusLabels[run.status] ?? run.status}</span></td>
                      <td>{run.processedObjects.toLocaleString()} / {run.discoveredObjects.toLocaleString()}{run.failedObjects ? <em>{run.failedObjects} failed</em> : null}</td>
                      <td>{run.parsedRecords.toLocaleString()}</td>
                      <td>{run.findingChanges.toLocaleString()}</td>
                      <td>{formatDate(run.startedAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="admin-empty compact">
              <Activity size={22} />
              <h3>No ingestion runs</h3>
              <p>A run appears after a verified source starts a backfill or receives an S3 object event.</p>
            </div>
          )}
        </section>
      ) : null}

      {data && tab === "access" ? (
        <div className="admin-two-column">
          <section className="panel">
            <div className="panel-header">
              <div><h2>Users and roles</h2><p>Server-enforced workspace authorization</p></div>
              <LockKeyhole size={18} />
            </div>
            <form
              className="role-form"
              onSubmit={(event) => {
                event.preventDefault();
                void settingAction({ action: "set-role", email: roleEmail, role: roleName });
              }}
            >
              <label><span>User email</span><input type="email" required value={roleEmail} onChange={(event) => setRoleEmail(event.target.value)} placeholder="analyst@example.com" /></label>
              <label><span>Role</span><select value={roleName} onChange={(event) => setRoleName(event.target.value)}><option value="admin">Administrator</option><option value="analyst">Security analyst</option><option value="reviewer">Reviewer</option><option value="viewer">Read-only auditor</option></select></label>
              <button className="button button-primary" disabled={saving}><Plus size={15} /> Assign role</button>
            </form>
            <div className="role-list">
              <div className="role-row current"><span className="avatar">LA</span><p><strong>{data.currentUser.email}</strong><small>Current local administrator</small></p><em>admin</em></div>
              {data.roles.map((role) => (
                <div className="role-row" key={role.email}>
                  <span className="avatar">{role.email.slice(0, 2).toUpperCase()}</span>
                  <p><strong>{role.email}</strong><small>Assigned by {role.createdBy}</small></p>
                  <em>{role.role}</em>
                  <button aria-label={`Remove ${role.email}`} onClick={() => void settingAction({ action: "remove-role", email: role.email })}><Trash2 size={14} /></button>
                </div>
              ))}
            </div>
          </section>
          <section className="panel role-definition-panel">
            <div className="panel-header"><div><h2>Role capabilities</h2><p>Default least-privilege separation</p></div></div>
            {[
              ["Administrator", "Sources, users, retention, retries, and all analyst workflows"],
              ["Security analyst", "Investigations, findings, policy, remediation simulation, and reports"],
              ["Reviewer", "Assigned reviews, campaigns, evidence exports, and exception decisions"],
              ["Read-only auditor", "Dashboards, evidence, history, and reports without mutations"],
            ].map(([name, detail]) => <article key={name}><BadgeCheck size={16} /><p><strong>{name}</strong><span>{detail}</span></p></article>)}
          </section>
        </div>
      ) : null}

      {data && tab === "integrations" ? (
        <div className="admin-two-column jira-admin-grid">
          <section className="panel ai-admin-panel">
            <div className="panel-header"><div><h2>Amazon Bedrock analyst</h2><p>Evidence-cited assistance with deterministic security controls</p></div><span className={`admin-status ${aiAnalyst?.status.enabled ? "status-live" : "status-draft"}`}><i />{aiAnalyst?.status.enabled ? "Available" : "Fallback only"}</span></div>
            <div className="ai-admin-identity"><span><BrainCircuit size={23} /></span><div><strong>{aiAnalyst?.status.modelId || "Deterministic Gatewatch fallback"}</strong><p>{aiAnalyst?.status.enabled ? `${aiAnalyst.status.region} · versioned Bedrock Guardrail ${aiAnalyst.status.guardrailConfigured ? aiAnalyst.status.guardrailVersion : "not configured"}` : "AWS inference is disabled or unavailable; core findings remain fully operational."}</p></div></div>
            {aiAnalystError ? <div className="form-error" role="alert"><CircleAlert size={15} />{aiAnalystError}</div> : null}
            <dl className="ai-admin-metrics"><div><dt>Your usage today</dt><dd>{aiAnalyst?.usage.personal.requests ?? 0} / {aiAnalyst?.limits.personal ?? 100}</dd></div><div><dt>Workspace usage</dt><dd>{aiAnalyst?.usage.workspaceRequests ?? 0} / {aiAnalyst?.limits.workspace ?? 500}</dd></div><div><dt>Output contract</dt><dd>Schema {aiAnalyst?.schemaVersion ?? "1.0"}</dd></div></dl>
            <div className="jira-permission-list"><div><CircleCheck size={14} /><span>Only normalized, bounded evidence packages leave the application</span></div><div><CircleCheck size={14} /><span>Strict JSON schema and evidence-reference validation</span></div><div><CircleCheck size={14} /><span>AI cannot alter risk, reachability, workflow, or AWS resources</span></div><div><CircleCheck size={14} /><span>Seven-day cache, daily budgets, audit trail, and analyst feedback</span></div></div>
            <footer><small>Model and guardrail changes are deployment-controlled to prevent browser-side policy bypass.</small><button className="button button-secondary" onClick={() => void loadAiAnalyst()}><RefreshCw size={14} />Refresh status</button></footer>
          </section>
          <section className="panel jira-configuration-panel">
            <div className="panel-header"><div><h2>Jira Cloud</h2><p>Create traceable remediation work directly from selected findings</p></div><span className={`admin-status ${jira?.configured ? "status-live" : "status-draft"}`}><i />{jira?.configured ? "Connected" : "Not configured"}</span></div>
            <div className="jira-security-note"><LockKeyhole size={17} /><p><strong>Token protected by AWS</strong><span>The API token is stored only in Secrets Manager and never returned to the browser or application database.</span></p></div>
            <div className="source-form-grid jira-form-grid">
              <label className="form-field source-span-two"><span>Jira Cloud site URL</span><input value={jiraDraft.baseUrl} onChange={(event) => setJiraDraft((current) => ({ ...current, baseUrl: event.target.value }))} placeholder="https://your-company.atlassian.net" /><small>Only HTTPS `*.atlassian.net` sites are accepted.</small></label>
              <label className="form-field"><span>Atlassian account email</span><input type="email" value={jiraDraft.email} onChange={(event) => setJiraDraft((current) => ({ ...current, email: event.target.value }))} placeholder="gatewatch-automation@example.com" /></label>
              <label className="form-field"><span>API token</span><input type="password" autoComplete="new-password" value={jiraDraft.apiToken} onChange={(event) => setJiraDraft((current) => ({ ...current, apiToken: event.target.value }))} placeholder={jira?.tokenStored ? "Stored securely — enter only to replace" : "Atlassian API token"} /></label>
              <label className="form-field"><span>Project key</span><input value={jiraDraft.projectKey} onChange={(event) => setJiraDraft((current) => ({ ...current, projectKey: event.target.value.toUpperCase() }))} placeholder="SEC" maxLength={20} /></label>
              <label className="form-field"><span>Issue type</span><select value={jiraDraft.issueType} onChange={(event) => setJiraDraft((current) => ({ ...current, issueType: event.target.value }))}>{jira?.issueTypes.length ? jira.issueTypes.map((name) => <option key={name}>{name}</option>) : <><option>Task</option><option>Bug</option><option>Story</option></>}</select></label>
            </div>
            {jiraError ? <div className="form-error" role="alert"><CircleAlert size={15} />{jiraError}</div> : null}
            <div className="jira-form-actions"><button className="button button-secondary" disabled={saving || !jira?.configured} onClick={() => void syncJiraIssues()}><RotateCcw size={15} className={saving ? "spin" : ""} />Sync linked issues</button><button className="button button-secondary" disabled={saving || (!jiraDraft.apiToken && !jira?.tokenStored)} onClick={() => void jiraAction("test")}><RefreshCw size={15} className={saving ? "spin" : ""} />Test connection</button><button className="button button-primary" disabled={saving || (!jiraDraft.apiToken && !jira?.tokenStored)} onClick={() => void jiraAction("save")}><Check size={15} />Save integration</button></div>
          </section>
          <section className="panel jira-integration-summary">
            <span><TicketCheck size={22} /></span>
            <h2>{jira?.configured ? `${jira.projectKey} is ready` : "Connect a remediation project"}</h2>
            <p>{jira?.configured ? `Selected findings create ${jira.issueType} issues in ${jira.projectName || jira.projectKey}. Existing links prevent duplicate tickets.` : "Use a dedicated Jira automation identity with Browse Projects and Create Issues permissions."}</p>
            {jira?.configured ? <dl><div><dt>Site</dt><dd><a href={jira.baseUrl} target="_blank" rel="noreferrer">{jira.baseUrl}<ExternalLink size={12} /></a></dd></div><div><dt>Identity</dt><dd>{jira.displayName || jira.email}</dd></div><div><dt>Last verified</dt><dd>{formatDate(jira.lastTestedAt)}</dd></div><div><dt>Issue type</dt><dd>{jira.issueType}</dd></div></dl> : null}
            <div className="jira-permission-list"><div><CircleCheck size={14} /><span>Credentials never reach finding payloads</span></div><div><CircleCheck size={14} /><span>Maximum 20 tickets per bulk request</span></div><div><CircleCheck size={14} /><span>Issue status and resolution reconcile back into Gatewatch</span></div><div><CircleCheck size={14} /><span>Every creation and synchronization is audited</span></div></div>
          </section>
          <section className="panel notification-routing-panel">
            <div className="panel-header"><div><h2>Notification routing</h2><p>Queue high-signal security events for your delivery adapter</p></div><span className={`admin-status ${notifications.enabled ? "status-live" : "status-draft"}`}><i />{notifications.enabled ? "Enabled" : "Paused"}</span></div>
            <div className="jira-security-note"><BellRing size={17} /><p><strong>Durable outbox</strong><span>Gatewatch persists matched notification events with recipients and retry state. Connect an email or webhook delivery worker in the AWS runtime to send them.</span></p></div>
            <div className="source-form-grid jira-form-grid">
              <label className="form-field source-span-two"><span>Recipients</span><input value={notificationRecipients} onChange={(event) => setNotificationRecipients(event.target.value)} placeholder="cloud-security@example.com, soc@example.com" /><small>Up to 20 comma-separated email addresses.</small></label>
              <label className="form-field"><span>Minimum severity</span><select value={notifications.minimumSeverity} onChange={(event) => setNotifications((current) => ({ ...current, minimumSeverity: event.target.value as NotificationSettings["minimumSeverity"] }))}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
              <label className="form-field"><span>Delivery cadence</span><select value={notifications.digest} onChange={(event) => setNotifications((current) => ({ ...current, digest: event.target.value as NotificationSettings["digest"] }))}><option value="immediate">Immediate</option><option value="daily">Daily digest</option></select></label>
            </div>
            <fieldset className="notification-event-list"><legend>Events</legend>{[["remediation.created", "Remediation drafted"], ["remediation.approved", "Remediation approved"], ["remediation.verification-failed", "Verification failed"]].map(([value, label]) => <label key={value}><input type="checkbox" checked={notifications.events.includes(value)} onChange={(event) => setNotifications((current) => ({ ...current, events: event.target.checked ? [...new Set([...current.events, value])] : current.events.filter((item) => item !== value) }))} /><span>{label}</span></label>)}</fieldset>
            <div className="jira-form-actions"><label className="notification-enabled"><input type="checkbox" checked={notifications.enabled} onChange={(event) => setNotifications((current) => ({ ...current, enabled: event.target.checked }))} /><span>Enable routing</span></label><button className="button button-primary" disabled={saving} onClick={() => void settingAction({ action: "notifications", ...notifications, recipients: notificationRecipients.split(",").map((value) => value.trim()).filter(Boolean) })}><Check size={15} />Save routing</button></div>
          </section>
        </div>
      ) : null}

      {data && tab === "retention" ? (
        <div className="admin-two-column">
          <section className="panel retention-form">
            <div className="panel-header"><div><h2>Normalized data retention</h2><p>Raw evidence remains governed by the source S3 lifecycle</p></div></div>
            <label><span>Normalized AWS evidence records</span><div><input type="number" min={30} max={3650} value={retention.eventDays} onChange={(event) => setRetention((current) => ({ ...current, eventDays: Number(event.target.value) }))} /><em>days</em></div><small>Used for configuration history, change attribution, observed traffic, path analysis, and threat context.</small></label>
            <label><span>Evidence snapshots and decisions</span><div><input type="number" min={90} max={3650} value={retention.evidenceDays} onChange={(event) => setRetention((current) => ({ ...current, evidenceDays: Number(event.target.value) }))} /><em>days</em></div><small>Preserves the facts considered during reviews and exceptions.</small></label>
            <label><span>Administrative audit trail</span><div><input type="number" min={365} max={3650} value={retention.auditDays} onChange={(event) => setRetention((current) => ({ ...current, auditDays: Number(event.target.value) }))} /><em>days</em></div><small>Seven years is the default for regulated environments.</small></label>
            <button className="button button-primary" disabled={saving} onClick={() => void settingAction({ action: "retention", ...retention })}><Check size={15} /> Save retention</button>
          </section>
          <section className="panel retention-boundary">
            <Archive size={21} />
            <h2>Deletion boundaries</h2>
            <p>Gatewatch retention jobs delete normalized database rows only. They never delete or modify the source AWS log objects.</p>
            <div><CircleCheck size={14} /><span>S3 remains the immutable source of truth</span></div>
            <div><CircleCheck size={14} /><span>Legal holds can override scheduled deletion</span></div>
            <div><CircleCheck size={14} /><span>Every purge produces an audit event and count</span></div>
          </section>
        </div>
      ) : null}

      {data && tab === "audit" ? (
        <section className="panel admin-table-panel">
          <div className="panel-header"><div><h2>Administrative audit log</h2><p>Configuration, connection, role, backfill, and retention events</p></div><span className="version-chip">{data.audits.length} events</span></div>
          {data.audits.length ? (
            <div className="audit-list">
              {data.audits.map((event) => (
                <article key={event.id}>
                  <span><FileClock size={16} /></span>
                  <p><strong>{event.summary}</strong><small>{event.actor} · {event.action} · {event.targetType}</small></p>
                  <time>{formatDate(event.createdAt)}</time>
                </article>
              ))}
            </div>
          ) : (
            <div className="admin-empty compact"><FileClock size={22} /><h3>No administrative events yet</h3><p>Creating a source or changing a role will start the audit history.</p></div>
          )}
        </section>
      ) : null}

      {wizardOpen ? (
        <div className="modal-layer" role="dialog" aria-modal="true" aria-labelledby="source-wizard-title">
          <button className="modal-scrim" aria-label="Close source wizard" onClick={() => setWizardOpen(false)} />
          <div className="admin-source-modal">
            <div className="modal-header">
              <div><p>Read-only AWS evidence</p><h2 id="source-wizard-title">{editingId ? "Edit log source" : "Add log source"}</h2><span>Step {wizardStep} of 3 · {wizardStep === 1 ? "Provider and location" : wizardStep === 2 ? "Read-only identity" : "Mapping and schedule"}</span></div>
              <button className="icon-button" aria-label="Close source wizard" onClick={() => setWizardOpen(false)}><X size={18} /></button>
            </div>
            <div className="wizard-progress"><span className={wizardStep >= 1 ? "active" : ""} /><span className={wizardStep >= 2 ? "active" : ""} /><span className={wizardStep >= 3 ? "active" : ""} /></div>
            <div className="modal-body">
              {wizardStep === 1 ? (
                <div className="source-form-grid">
                  <label className="form-field"><span>Source name</span><input autoFocus value={draft.name} maxLength={120} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} placeholder="Organization AWS evidence" /></label>
                  <label className="form-field"><span>Provider</span><select value={draft.provider} onChange={(event) => setDraft((current) => ({ ...current, provider: event.target.value as SourceProvider }))}><option value="aws-s3">Amazon S3</option><option value="azure-data-explorer">Azure Data Explorer</option></select><small>Choose where the AWS log records are stored.</small></label>
                  <label className="form-field source-span-two"><span>AWS evidence type</span><select value={draft.sourceType} onChange={(event) => setDraft((current) => ({ ...current, sourceType: event.target.value as SourceType }))}>{[...new Set(sourceTypeDefinitions.map((definition) => definition.group))].map((group) => <optgroup key={group} label={group}>{sourceTypeDefinitions.filter((definition) => definition.group === group).map((definition) => <option key={definition.value} value={definition.value}>{definition.label}</option>)}</optgroup>)}</select><small>{sourceTypeDefinition(draft.sourceType).description} Expected record shape: {sourceTypeDefinition(draft.sourceType).format}.</small></label>
                  {draft.provider === "aws-s3" ? <>
                    <label className="form-field source-span-two"><span>S3 bucket ARN</span><input value={draft.bucketArn} onChange={(event) => setDraft((current) => ({ ...current, bucketArn: event.target.value }))} placeholder="arn:aws:s3:::organization-security-logs" /><small>Enter the bucket ARN, not an HTTPS URL.</small></label>
                    <label className="form-field"><span>AWS region</span><input value={draft.region} onChange={(event) => setDraft((current) => ({ ...current, region: event.target.value }))} placeholder="us-east-1" /></label>
                    <label className="form-field"><span>Object prefix</span><input value={draft.objectPrefix} onChange={(event) => setDraft((current) => ({ ...current, objectPrefix: event.target.value }))} placeholder="AWSLogs/o-example/" /></label>
                    <label className="form-field source-span-two"><span>AWS Organizations ID <em>Optional</em></span><input value={draft.organizationId} onChange={(event) => setDraft((current) => ({ ...current, organizationId: event.target.value }))} placeholder="o-a1b2c3d4e5" /></label>
                  </> : <>
                    <label className="form-field source-span-two"><span>ADX cluster URL</span><input value={draft.adxClusterUrl} onChange={(event) => setDraft((current) => ({ ...current, adxClusterUrl: event.target.value }))} placeholder="https://securitylogs.eastus.kusto.windows.net" /><small>Only HTTPS Microsoft Kusto cluster domains are accepted; paths and query strings are rejected.</small></label>
                    <label className="form-field"><span>Database</span><input value={draft.adxDatabase} onChange={(event) => setDraft((current) => ({ ...current, adxDatabase: event.target.value }))} placeholder="SecurityLogs" /></label>
                    <label className="form-field"><span>Table</span><input value={draft.adxTable} onChange={(event) => setDraft((current) => ({ ...current, adxTable: event.target.value }))} placeholder="AwsEvidence" /></label>
                  </>}
                </div>
              ) : null}
              {wizardStep === 2 ? (
                <div className="source-permission-step">
                  {draft.provider === "aws-s3" ? <>
                    <div className="permission-banner"><KeyRound size={19} /><p><strong>Use a dedicated cross-account role</strong><span>Gatewatch assumes this role only to list the configured prefix and read delivered objects.</span></p></div>
                    <label className="form-field"><span>IAM role ARN</span><input value={draft.roleArn} onChange={(event) => setDraft((current) => ({ ...current, roleArn: event.target.value }))} placeholder="arn:aws:iam::123456789012:role/GatewatchLogReadRole" /></label>
                    <label className="form-field"><span>External ID</span><div className="copy-input"><input readOnly value={draft.externalId} /><button aria-label="Copy external ID" onClick={() => { void navigator.clipboard.writeText(draft.externalId); onToast("External ID copied."); }}><Copy size={15} /></button></div><small>Include this unique value in the role trust policy.</small></label>
                    <label className="form-field"><span>Customer-managed KMS key ARN <em>Optional</em></span><input value={draft.kmsKeyArn} onChange={(event) => setDraft((current) => ({ ...current, kmsKeyArn: event.target.value }))} placeholder="arn:aws:kms:us-east-1:123456789012:key/…" /></label>
                    <button
                    className="button button-secondary template-preview-button"
                    disabled={!draft.bucketArn || !draft.region}
                    onClick={() => {
                      const preview = {
                        ...draft,
                        id: "preview",
                        bucketName: draft.bucketArn.replace(/^arn:[^:]+:s3:::/, ""),
                        includedAccounts: [],
                        excludedAccounts: [],
                        includedRegions: [],
                        status: "draft" as const,
                      };
                      download(`gatewatch-${draft.sourceType}-read-role.yaml`, sourceAccessCloudFormation(preview));
                      onToast("Downloaded a prefix-scoped IAM role template.");
                    }}
                  >
                    <Download size={15} /> Download role template
                    </button>
                  </> : <>
                    <div className="permission-banner"><KeyRound size={19} /><p><strong>Use a dedicated database viewer</strong><span>Grant the Entra application viewer access only to the configured ADX database. Gatewatch stores its secret in the isolated AWS credential vault.</span></p></div>
                    <label className="form-field"><span>Microsoft Entra tenant ID</span><input value={draft.adxTenantId} onChange={(event) => setDraft((current) => ({ ...current, adxTenantId: event.target.value }))} placeholder="00000000-0000-4000-8000-000000000000" /></label>
                    <label className="form-field"><span>Application (client) ID</span><input value={draft.adxClientId} onChange={(event) => setDraft((current) => ({ ...current, adxClientId: event.target.value }))} placeholder="00000000-0000-4000-8000-000000000000" /></label>
                    <label className="form-field"><span>Client secret {editingId ? <em>Optional when unchanged</em> : null}</span><input type="password" autoComplete="new-password" value={draft.adxClientSecret} onChange={(event) => setDraft((current) => ({ ...current, adxClientSecret: event.target.value }))} placeholder={editingId ? "Stored securely — enter only to replace" : "Microsoft Entra client secret"} /><small>The authenticated server immediately relays this to the isolated AWS bridge; it is never stored in the application database.</small></label>
                  </>}
                </div>
              ) : null}
              {wizardStep === 3 ? (
                <div className="source-form-grid">
                  <label className="form-field"><span>Ingestion mode</span><select value={draft.ingestionMode} onChange={(event) => setDraft((current) => ({ ...current, ingestionMode: event.target.value as SourceDraft["ingestionMode"] }))}><option value="both">Continuous + historical backfill</option><option value="continuous">Continuous deliveries only</option><option value="backfill">Historical backfill only</option></select></label>
                  <label className="form-field"><span>Backfill start</span><input type="date" disabled={draft.ingestionMode === "continuous"} value={draft.backfillStart} onChange={(event) => setDraft((current) => ({ ...current, backfillStart: event.target.value }))} /></label>
                  {draft.provider === "azure-data-explorer" ? <>
                    <label className="form-field"><span>Timestamp column</span><input value={draft.adxTimestampColumn} onChange={(event) => setDraft((current) => ({ ...current, adxTimestampColumn: event.target.value }))} placeholder="TimeGenerated" /><small>Used for deterministic incremental checkpoints.</small></label>
                    <label className="form-field"><span>Row mapping</span><select value={draft.adxQueryMode} onChange={(event) => setDraft((current) => ({ ...current, adxQueryMode: event.target.value as SourceDraft["adxQueryMode"] }))}><option value="whole-row">Use the complete ADX row</option><option value="payload-column">Parse one dynamic/JSON column</option></select></label>
                    <label className="form-field"><span>Payload column</span><input disabled={draft.adxQueryMode === "whole-row"} value={draft.adxPayloadColumn} onChange={(event) => setDraft((current) => ({ ...current, adxPayloadColumn: event.target.value }))} placeholder="RawEvent" /></label>
                    <label className="form-field"><span>Rows per sync</span><input type="number" min={10} max={1000} value={draft.adxBatchSize} onChange={(event) => setDraft((current) => ({ ...current, adxBatchSize: Number(event.target.value) }))} /><small>Hard limit: 1,000 rows and 5 MB per query.</small></label>
                  </> : null}
                  <label className="form-field"><span>Included accounts <em>Optional</em></span><textarea value={draft.includedAccounts} onChange={(event) => setDraft((current) => ({ ...current, includedAccounts: event.target.value }))} placeholder="111122223333, 444455556666" /><small>Leave blank to accept every account in the source.</small></label>
                  <label className="form-field"><span>Included regions <em>Optional</em></span><textarea value={draft.includedRegions} onChange={(event) => setDraft((current) => ({ ...current, includedRegions: event.target.value }))} placeholder="us-east-1, us-west-2" /><small>Leave blank to accept every delivered region.</small></label>
                  <label className="form-field"><span>Excluded accounts <em>Optional</em></span><textarea value={draft.excludedAccounts} onChange={(event) => setDraft((current) => ({ ...current, excludedAccounts: event.target.value }))} placeholder="999900001111" /></label>
                  <label className="form-field"><span>Normalized retention</span><div className="input-suffix"><input type="number" min={30} max={3650} value={draft.retentionDays} onChange={(event) => setDraft((current) => ({ ...current, retentionDays: Number(event.target.value) }))} /><em>days</em></div></label>
                  {isConfigSource(draft.sourceType) ? (
                    <div className="config-types source-span-two">
                      <span>Config resource types</span>
                      {defaultConfigResourceTypes.map((resourceType) => (
                        <label key={resourceType}><input type="checkbox" checked={draft.configResourceTypes.includes(resourceType)} onChange={(event) => setDraft((current) => ({ ...current, configResourceTypes: event.target.checked ? [...current.configResourceTypes, resourceType] : current.configResourceTypes.filter((item) => item !== resourceType) }))} />{resourceType}</label>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : null}
              {error ? <div className="form-error" role="alert"><CircleAlert size={15} />{error}</div> : null}
            </div>
            <div className="modal-footer">
              <button className="button button-secondary" onClick={() => wizardStep === 1 ? setWizardOpen(false) : setWizardStep((step) => step - 1)}>{wizardStep === 1 ? "Cancel" : "Back"}</button>
              {wizardStep < 3 ? (
                <button className="button button-primary" onClick={() => setWizardStep((step) => step + 1)}>Continue <ChevronRight size={15} /></button>
              ) : (
                <button className="button button-primary" disabled={saving} onClick={() => void createSource()}>{saving ? <><RefreshCw size={15} className="spin" />Saving…</> : <><Check size={15} />{editingId ? "Save changes" : "Save draft"}</>}</button>
              )}
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
