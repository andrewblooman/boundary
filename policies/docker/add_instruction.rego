# METADATA
# title: Prefer COPY over ADD
# description: >
#   ADD has implicit magic — remote URL fetches with no integrity check and
#   automatic archive extraction — that widens the supply-chain surface.
#   COPY does exactly one auditable thing.
# custom:
#   id: BND-DK-005
#   severity: LOW
#   target: docker
#   compliance:
#     soc2: [CC8.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: []
#   remediation: |
#     Replace ADD with COPY for local files. For remote content, download with
#     curl/wget plus checksum verification in a RUN step (or use
#     `ADD --checksum=sha256:... URL` on modern BuildKit).
#   fix_hint: change_value
#   references:
#     - https://docs.docker.com/build/building/best-practices/#add-or-copy
package boundary.docker.add_instruction

import data.boundary.lib

deny contains finding if {
	some inst in input.instructions
	inst.cmd == "ADD"
	not contains(inst.value, "--checksum")
	finding := lib.finding(
		rego.metadata.chain(),
		{"name": input.file, "_src": {"file": input.file, "line": inst.line}},
		{"value": inst.value},
	)
}
