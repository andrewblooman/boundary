# METADATA
# title: Images must not expose SSH
# description: >
#   An SSH daemon in a container is a second, unmanaged remote-access path
#   with its own keys and its own patching burden. Containers should be
#   replaced, not logged into.
# custom:
#   id: BND-DK-007
#   severity: MEDIUM
#   target: docker
#   compliance:
#     soc2: [CC6.1, CC6.6]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Remove `EXPOSE 22` and any sshd installation. Use the orchestrator's
#     exec facility (docker exec, kubectl exec / debug containers) for
#     interactive access.
#   fix_hint: remove_block
#   references:
#     - https://docs.docker.com/build/building/best-practices/
package boundary.docker.expose_ssh

import data.boundary.lib

deny contains finding if {
	some inst in input.instructions
	inst.cmd == "EXPOSE"
	some port in split(inst.value, " ")
	trim_space(split(port, "/")[0]) == "22"
	finding := lib.finding(
		rego.metadata.chain(),
		{"name": input.file, "_src": {"file": input.file, "line": inst.line}},
		{"exposed": port},
	)
}
