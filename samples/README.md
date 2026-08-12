# Gatewatch AWS evidence samples

## Infrastructure-as-code review

`iac-review/` contains CloudFormation YAML, Terraform HCL, and Terraform JSON
examples for **Recommendations → IaC guardrails**. Upload the three numbered
files together to exercise multi-file static analysis, public-path signals,
critical administration/database findings, and a private security-group
reference. These are intentionally incomplete review fixtures and are not
deployable production templates.

## Mixed AWS evidence batch

`aws-evidence-batch/` is a deterministic, entirely synthetic investigation
pack designed to be uploaded as one mixed selection in **Reports → AWS log
imports**. It contains 14 source files covering:

- AWS Config snapshot and history
- AWS CloudTrail, including an exact duplicate event and a failed request
- VPC Flow Logs
- Reachability Analyzer and Network Access Analyzer
- ALB, WAF, CloudFront, API Gateway, Route 53 Resolver, and Network Firewall logs
- GuardDuty and Security Hub findings

Every file follows an AWS-native shape and shares a coherent payments-service
scenario. Config relationships and nested AWS resource context provide the
correlation paths. Two records are duplicated intentionally to validate
suppression. Network Firewall evidence is intentionally left unmatched because
the sample does not invent a direct firewall-to-security-group relationship.

Upload every numbered file together; `manifest.json` is documentation and
should not be uploaded. The expected outcome is one consolidated finding for
`sg-0a41f2e91b71`, one for `sg-0d3c99118aae`, two suppressed records, and an
explicit unmatched Network Firewall record set.

Regenerate the pack from the repository root with:

```bash
npm run sample:aws-evidence
```

All account IDs, resource IDs, addresses, events, principals, requests, and
findings are synthetic. Documentation-only IPv4 ranges are used for external
addresses, and the pack contains no credentials or customer data.

## CloudTrail volume sample

`cloudtrail-security-groups-50000.json.gz` is a deterministic synthetic
CloudTrail management-event log containing exactly 50,000 records.

The sample includes:

- Public ingress authorization using `0.0.0.0/0`
- Unrestricted egress authorization
- Security-group rule modifications
- Ingress and egress revocations
- Security-group create and delete events
- Rule-description changes
- Failed API calls
- Unrelated EC2 events that the importer should ignore
- Group IDs matching Gatewatch's demonstration inventory

The identities, IP addresses, account IDs, request IDs, and events are
synthetic. The file contains no real AWS credentials or customer data.

Validated sample:

- Total CloudTrail records: 50,000
- Supported security-group events: 40,000
- Unrelated events intentionally skipped: 10,000
- Successful internet-wide changes detected: 12,372
- SHA-256:
  `aea1976a24114b9b6b216369d74b16cc5d6d67d584665d96caad2a7986529be0`

Regenerate it from the repository root with:

```bash
npm run sample:cloudtrail
```

## Detailed investigation sample

`cloudtrail-security-groups-detailed-10000.json.gz` is the scenario-rich
companion sample. It contains 10,000 deterministic records and is intended for
analyst workflow, attribution, correlation, and parser edge-case testing rather
than maximum-volume testing.

It adds:

- Assumed-role, IAM user, AWS service, IAM Identity Center-style, and federated
  identities with session issuer, MFA, and source-identity context
- Terraform, AWS Console, CLI, CloudFormation, and SDK user agents
- Public IPv4 and IPv6 ingress, unrestricted egress, private CIDRs,
  security-group references, managed prefix lists, and multi-rule requests
- Full authorize, revoke, modify, description, create, and delete event shapes
- Response rule IDs, resource ARNs, TLS metadata, VPC endpoint IDs, and shared
  event IDs
- Deterministic failed requests and duplicate event IDs for negative-path and
  idempotency testing
- Security-group IDs that correlate with the current personal AWS test
  deployment; all identities, IP addresses, and event contents are synthetic

Regenerate it with:

```bash
npm run sample:cloudtrail:detailed
```

Validated detailed sample:

- Total CloudTrail records: 10,000
- Supported security-group events: 8,572
- Unrelated events intentionally skipped: 1,428
- Successful internet-wide changes detected: 2,833
- Failed API calls: 88
- Duplicate event IDs: 10
- Decompressed size: 16,289,242 bytes
- SHA-256:
  `dc8030249bc381798bacaa8e50a23bddda35d85d0741cb99b06b1bf06cd5be75`
