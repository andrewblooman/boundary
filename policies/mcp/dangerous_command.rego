# METADATA
# title: MCP server commands must not contain dangerous execution patterns
# description: >
#   The command line in an MCP config runs on every client start with the
#   user's full privileges. Piped remote scripts, shell -c wrappers around
#   downloads, or sudo in the command are an unauditable code-execution
#   channel — exactly how poisoned MCP entries persist.
# custom:
#   id: BND-MCP-004
#   severity: CRITICAL
#   target: mcp
#   compliance:
#     soc2: [CC6.8, CC8.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(c)(1)]
#   remediation: |
#     Launch a pinned, locally-installed binary or package directly. Remove
#     curl|sh style bootstrapping and sudo; if installation is needed, do it
#     once, explicitly, outside the MCP config.
#   fix_hint: remove_block
#   references:
#     - https://modelcontextprotocol.io/docs/concepts/architecture
package boundary.mcp.dangerous_command

import data.boundary.lib

patterns := [
	`(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh`,
	`^sudo$|^sudo\s`,
	`rm\s+-rf\s+[/~]`,
	`base64\s+(-d|--decode)`,
]

deny contains finding if {
	some server in input.servers
	full := concat(" ", array.concat([server.command], server.args))
	some pattern in patterns
	regex.match(pattern, full)
	finding := lib.finding(rego.metadata.chain(), server, {
		"server": server.name,
		"command": full,
	})
}
