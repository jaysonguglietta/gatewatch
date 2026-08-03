# Gatewatch security policy

Gatewatch analyzes AWS security-group configuration, resource relationships,
CloudTrail activity, AWS Config evidence, review decisions, and Jira remediation
records. A vulnerability in Gatewatch can therefore affect sensitive cloud
inventory or the integrity of security decisions across many AWS accounts.

## Reporting a vulnerability

Do not open a public GitHub issue for a suspected vulnerability.

Use GitHub's private vulnerability-reporting feature for this repository. Include:

- the affected version, commit, route, component, or CloudFormation resource;
- prerequisites and a minimal reproducible example;
- the expected and observed security behavior;
- the confidentiality, integrity, and availability impact;
- relevant logs with credentials, account IDs, tokens, and customer data removed;
- any suggested mitigation or regression test.

If private vulnerability reporting is unavailable, contact the repository owner
through a private, verified channel and request a secure reporting path. Do not
send secrets or production evidence in ordinary email.

## Response expectations

The maintainers should acknowledge a complete report within three business days,
provide an initial severity assessment within seven business days, and coordinate
disclosure after a fix or effective mitigation is available. These are targets,
not a contractual service-level agreement.

## Supported versions

Gatewatch is not yet designated production-ready. Until a versioned release policy
is published, only the current default branch is expected to receive security
fixes.

## Security documentation

The security review package is maintained under [`docs/security`](docs/security/README.md):

- architecture and threat model;
- dated adversarial audit;
- prioritized remediation roadmap;
- security regression and infrastructure test plan.

## Secret-handling rules

- Never commit AWS credentials, Jira tokens, Basic Auth passwords, origin tokens,
  exported customer logs, or unredacted CloudTrail evidence.
- Use short-lived workload identities and AWS Secrets Manager.
- Redact AWS account IDs, role session names, source IP addresses, emails, and
  customer tags from public issues and screenshots.
- Rotate a credential immediately if it is displayed in logs, a terminal capture,
  an issue, a pull request, or chat.

