# IaC security review samples

Drop these files together into **Recommendations → IaC guardrails**.

- `01-cloudformation-public-admin.yaml` intentionally exposes SSH and RDP and
  includes enough template evidence for a potential internet path.
- `02-terraform-public-database.tf` intentionally exposes PostgreSQL through a
  public database configuration.
- `03-terraform-private-service.tf.json` demonstrates a security-group reference
  that should not be treated as internet-wide access.

The examples are static review fixtures. They are not complete deployable stacks
and must never be used as production infrastructure.
