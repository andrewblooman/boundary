# Writing a Boundary policy

Adding a policy is adding **one annotated Rego file**. Nothing to register:
the engine discovers policies from the directory layout and reads all
metadata from the `# METADATA` block.

## The contract

```rego
# METADATA
# title: <imperative statement of the rule>
# description: >
#   Why this matters — written for a non-security reader. This text goes
#   verbatim into scan results and AI analysis.
# custom:
#   id: BND-<TARGET>-<NNN>        # unique; see prefixes below
#   severity: HIGH                 # CRITICAL | HIGH | MEDIUM | LOW | INFO
#   target: terraform              # terraform | docker | kubernetes | mcp | skills
#   compliance:                    # controls this rule maps to (any subset)
#     soc2: [CC6.1]
#     dora: [Art.9.2]
#     nis2: [Art.21.2h]
#     hipaa: [164.312(a)(2)(iv)]
#   remediation: |
#     Concrete instructions for fixing the finding.
#   fix_hint: add_block            # add_block | change_value | remove_block | review
#   references:
#     - https://...
package boundary.<target>.<policy_name>

import data.boundary.lib

deny contains finding if {
    # ... detection logic over `input` (see input shapes below) ...
    finding := lib.finding(rego.metadata.chain(), src_object, {"observed": "value"})
}
```

Rules:

- **File**: `policies/<target>/<policy_name>.rego`, package
  `boundary.<target>.<policy_name>`. One concern per file.
- **ID prefixes**: `BND-TF-` terraform, `BND-DK-` docker, `BND-K8-`
  kubernetes, `BND-MCP-` mcp, `BND-SK-` skills.
- **Finding construction**: always via `lib.finding(rego.metadata.chain(),
  src, observed)`. `src` is the adapter object being flagged (it carries
  `_src` file/line); `observed` is a small dict of what was actually seen.
- **Tests**: add cases to `tests/policies/<target>_test.rego` — at least one
  input that triggers the rule and one that passes.
- **Severity guide**: CRITICAL = exploitable now / credential exposure;
  HIGH = serious weakness; MEDIUM = hardening gap; LOW = hygiene;
  INFO = advisory.
- **fix_hint** tells an AI what shape of change fixes the finding; use
  `review` when human judgment is genuinely required.

## Input shapes (produced by the Python adapters)

- `terraform`: `{"kind", "source": "plan"|"hcl", "resources": [{"type",
  "name", "address", "mode", "values", "_src": {"file", "line"}}]}`
- `docker`: `{"kind", "file", "instructions": [{"cmd", "value", "line"}],
  "stages": [...]}`
- `kubernetes`: `{"kind", "file", "objects": [{"apiVersion", "kind", "name",
  "manifest", "_src"}]}` — use `data.boundary.lib.k8s` helpers
  (`pod_spec`, `containers`, `is_workload`) instead of walking manifests.
- `mcp`: `{"kind", "file", "servers": [{"name", "command", "args", "env",
  "url", "headers", "transport", "_src"}]}`
- `skills`: `{"kind", "dir", "file", "frontmatter", "body", "scripts":
  [{"path", "ext", "content", "_src"}]}`

## Shared helpers (`data.boundary.lib`)

- `lib.finding(chain, src, observed)` — the uniform finding object
- `lib.as_array(x)` — normalizes HCL single-block vs repeated-block values
- `lib.is_true(x)` — true for `true` and `"true"`
- `lib.looks_like_secret_name(name)` / `lib.is_literal_secret(value)`
- `lib.references(values, address)` — cross-resource reference check (HCL)

## Verify before committing

```bash
opa check --strict --v1-compatible policies/
opa fmt --v1-compatible -w policies/ tests/policies/
regal lint policies/ tests/policies/
opa test policies/ tests/policies/
pytest -q          # test_policy_metadata_complete enforces the metadata contract
```
