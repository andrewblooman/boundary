# METADATA
# title: Long-running images should define a HEALTHCHECK
# description: >
#   Without a HEALTHCHECK the runtime can only see whether the process exists,
#   not whether it works. Hung or half-crashed containers keep receiving
#   traffic, which is an availability and incident-response gap.
# custom:
#   id: BND-DK-006
#   severity: INFO
#   target: docker
#   compliance:
#     soc2: [A1.1]
#     dora: [Art.10]
#     nis2: [Art.21.2c]
#     hipaa: []
#   remediation: |
#     Add e.g. `HEALTHCHECK --interval=30s --timeout=3s CMD curl -f
#     http://localhost:8080/health || exit 1` (skip for one-shot job images;
#     Kubernetes users may rely on probes instead).
#   fix_hint: add_block
#   references:
#     - https://docs.docker.com/reference/dockerfile/#healthcheck
package boundary.docker.healthcheck

import data.boundary.lib

deny contains finding if {
	exposes_port
	not has_healthcheck
	finding := lib.finding(
		rego.metadata.chain(),
		{"name": input.file, "_src": {"file": input.file, "line": 1}},
		{"healthcheck": "missing"},
	)
}

# Only images that EXPOSE a port look like long-running services.
exposes_port if {
	some inst in input.instructions
	inst.cmd == "EXPOSE"
}

has_healthcheck if {
	some inst in input.instructions
	inst.cmd == "HEALTHCHECK"
}
