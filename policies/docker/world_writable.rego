# METADATA
# title: RUN must not create world-writable permissions
# description: >
#   chmod 777 (or o+w) lets any process in the container modify the files —
#   a common lazy fix for permission errors that turns config and binaries
#   into tampering targets.
# custom:
#   id: BND-DK-008
#   severity: MEDIUM
#   target: docker
#   compliance:
#     soc2: [CC6.1, CC6.8]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(c)(1)]
#   remediation: |
#     Chown the path to the runtime user instead of opening permissions:
#     `COPY --chown=app:app ...` or `RUN chown -R app:app /app && chmod 755
#     /app`.
#   fix_hint: change_value
#   references:
#     - https://docs.docker.com/build/building/best-practices/
package boundary.docker.world_writable

import data.boundary.lib

pattern := `chmod\s+(-[A-Za-z]+\s+)*(777|666|a\+rwx|o\+w)`

deny contains finding if {
	some inst in input.instructions
	inst.cmd == "RUN"
	regex.match(pattern, inst.value)
	finding := lib.finding(
		rego.metadata.chain(),
		{"name": input.file, "_src": {"file": input.file, "line": inst.line}},
		{"command": inst.value},
	)
}
