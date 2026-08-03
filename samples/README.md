# Gatewatch CloudTrail samples

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
