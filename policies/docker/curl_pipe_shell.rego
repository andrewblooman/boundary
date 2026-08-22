# METADATA
# title: RUN must not pipe downloads straight into a shell
# description: >
#   `curl ... | sh` executes whatever the remote server returns, with no
#   integrity check and no review. A compromised or MITM'd download becomes
#   arbitrary code execution inside the build.
# custom:
#   id: BND-DK-004
#   severity: HIGH
#   target: docker
#   compliance:
#     soc2: [CC6.8, CC8.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(c)(1)]
#   remediation: |
#     Download to a file, verify a pinned checksum or signature, then execute:
#     `curl -fsSLo tool.sh URL && echo "<sha256>  tool.sh" | sha256sum -c -
#     && sh tool.sh`. Prefer distro packages or COPY'd vendored installers.
#   fix_hint: change_value
#   references:
#     - https://docs.docker.com/build/building/best-practices/
package boundary.docker.curl_pipe_shell

import data.boundary.lib

pipe_pattern := `(curl|wget)[^|;&]*(\|\s*|\|\s*sudo\s+)(ba|z|da)?sh`

deny contains finding if {
	some inst in input.instructions
	inst.cmd == "RUN"
	regex.match(pipe_pattern, inst.value)
	finding := lib.finding(
		rego.metadata.chain(),
		{"name": input.file, "_src": {"file": input.file, "line": inst.line}},
		{"command": inst.value},
	)
}
