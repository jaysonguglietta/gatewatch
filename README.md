# Gatewatch

Gatewatch is an AWS security-group posture dashboard for evidence-backed
investigation and review. It correlates deployed rules with policy intent,
effective connectivity, VPC Flow Log usage, CloudTrail provenance, attached
resources, and vulnerability context.

## Product surfaces

- Posture overview ranked by reachable risk
- Explainable findings inventory with search, filters, and CSV export
- Interactive connectivity paths with traffic and attachment evidence
- Durable review decisions, ticket references, evidence snapshots, and
  expiring exceptions
- CloudTrail before/after change evidence and delivery-channel attribution
- Read-only remediation simulation with transparent risk factors
- Collection coverage for Config, CloudTrail, Flow Logs, Inspector, Security
  Hub, and Terraform access manifests

The current dataset is realistic and intentionally isolated behind typed models
so live AWS collectors can replace it without restructuring the user
experience.

## Local development

Prerequisites: Node.js `>=22.13.0`.

```bash
npm install
npm run dev
```

Useful checks:

```bash
npm run build
npm run lint
node --test tests/rendered-html.test.mjs
```

Review decisions are persisted through the configured Cloudflare D1 `DB`
binding. Schema changes live in `db/schema.ts` and generated migrations are
stored in `drizzle/`.
