# Time-bounded security exceptions

Security exceptions are narrow release artifacts, not permanent scanner
suppressions. Every exception must identify the exact control, affected path,
compensating controls, accountable owner, review date, and removal plan. CI must
fail automatically after the expiration date.

## SEC-EX-001 — private workload HTTPS egress

| Field | Decision |
|---|---|
| Status | Accepted temporarily |
| Owner | Gatewatch security maintainer |
| Review / expiration | 2026-11-12 |
| Scanner rule | `AWS-0104` |
| Exact path | `WebSecurityGroup` in `gatewatch-aws-web.yaml` |
| Required access | TCP/443 through the NAT gateway to Cognito, STS, Bedrock, the approved Jira tenant, and the pinned container registry |
| Compensating controls | Private instance and ALB subnets; CloudFront VPC origin; no public IP; TCP/443-only egress; read-only evidence access; a separate scoped bridge role; IMDS denied to web and OIDC containers; restrictive container capabilities and filesystems; WAF and immutable security logging |
| Removal plan | Add AWS service VPC endpoints and route remaining SaaS traffic through an authenticated FQDN allowlisting proxy, then remove `0.0.0.0/0` egress and this exception |

The matching entry in the root `.trivyignore.yaml` is path-scoped and expires on
the same date. Extending it requires a new review and dated justification.
