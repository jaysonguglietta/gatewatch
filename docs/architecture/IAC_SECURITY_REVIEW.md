# IaC security review architecture

## Trust boundary

Infrastructure files are attacker-controlled input. Gatewatch reads them in the
browser, applies strict file-count and byte limits, and parses them as inert data.
The review path contains no shell, subprocess, Terraform, CloudFormation,
provider, module, macro, hook, network, or filesystem execution capability.

Original contents are not uploaded or persisted. Only the in-memory normalized
review is rendered. React output encoding prevents parsed strings from becoming
HTML. CSV export uses the existing formula-safe CSV encoder.

## Supported definitions

CloudFormation:

- YAML and JSON templates
- `AWS::EC2::SecurityGroup`
- `AWS::EC2::SecurityGroupIngress`
- `AWS::EC2::SecurityGroupEgress`
- common short-form intrinsic tags as unresolved data
- internet gateway, default route, public IP, public load balancer, and
  `PubliclyAccessible` context signals

Terraform:

- native HCL `.tf` and Terraform JSON `.tf.json`
- `aws_security_group` nested rule blocks
- `aws_security_group_rule`
- `aws_vpc_security_group_ingress_rule`
- `aws_vpc_security_group_egress_rule`
- simple variable defaults, resource references, and cross-file consolidation
- internet gateway, default route, EIP/public IP, load balancer, and public
  managed-service context signals

## Analysis model

`lib/iac-security-review.ts` normalizes every rule into direction, protocol,
ports, sources, description, source file, resource address, and line. Duplicate
rules are suppressed before policy checks. Issues are generated for public
administration/data/development access, all traffic, wide ranges, broad private
CIDRs, unrestricted egress, missing descriptions, and unresolved expressions.

The group risk score is deterministic and capped at 100. A critical issue blocks;
high or medium issues require review; low-only or no issues pass. This verdict is
a source-review decision, not a deployed reachability claim.

## Exposure semantics

A public CIDR rule alone produces `unknown`. It becomes `potential-internet`
only when the uploaded batch also contains an internet gateway, public default
route, and public attachment/service signal. `internal-only` means no unrestricted
ingress was parsed, not that all internal access is least privilege.

## Known static-analysis limits

- Macros, transforms, conditions, nested stacks, and StackSet targets are not resolved.
- Terraform modules, `for_each`, dynamic blocks, functions, provider defaults,
  remote state, data sources, and computed values are not executed.
- HCL heredocs and highly generated expressions may be retained as unresolved.
- Account, Region, deployed ARN, listener state, NACLs, and actual routing require
  CI plan metadata or AWS evidence.

These conditions fail visibly as parser warnings or unresolved-expression issues;
they are never treated as proof that access is safe.
