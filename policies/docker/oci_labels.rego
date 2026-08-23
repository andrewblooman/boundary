# METADATA
# title: Images must include OCI source, version, and description labels
# description: >
#   OCI metadata links a deployed image to its source, version, and purpose.
#   Without it, incident response and supply-chain tracing cannot reliably
#   identify what code produced a running artifact.
# custom:
#   id: BND-DK-009
#   severity: LOW
#   target: docker
#   compliance:
#     soc2: [CC2.1, CC8.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2i]
#     hipaa: [164.308(a)(1)(ii)(A)]
#   remediation: |
#     Add LABEL instructions for org.opencontainers.image.source,
#     org.opencontainers.image.version, and
#     org.opencontainers.image.description with non-empty values.
#   fix_hint: add_block
#   references:
#     - https://github.com/opencontainers/image-spec/blob/main/annotations.md
package boundary.docker.oci_labels

import data.boundary.lib

required_labels := {
	"org.opencontainers.image.source",
	"org.opencontainers.image.version",
	"org.opencontainers.image.description",
}

deny contains finding if {
	missing := {label | some label in required_labels; not has_label(label)}
	count(missing) > 0
	finding := lib.finding(
		rego.metadata.chain(),
		{"name": input.file, "_src": {"file": input.file, "line": 1}},
		{"missing_labels": sort(missing)},
	)
}

has_label(label) if {
	some inst in input.instructions
	inst.cmd == "LABEL"
	regex.match(sprintf(`(?i)(^|\s)%s\s*=\s*("[^"]+"|'[^']+'|[^\s]+)`, [label]), inst.value)
}
