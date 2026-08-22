# METADATA
# title: MCP server configs must not contain literal secrets
# description: >
#   MCP config files (.mcp.json, claude_desktop_config.json) are routinely
#   committed and synced across machines. A literal API key in a server's env
#   block is a credential leak with agent-level blast radius: every tool the
#   server exposes runs with it.
# custom:
#   id: BND-MCP-001
#   severity: CRITICAL
#   target: mcp
#   compliance:
#     soc2: [CC6.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2j]
#     hipaa: [164.312(a)(2)(i)]
#   remediation: |
#     Reference the secret from the process environment instead of inlining it
#     (e.g. "API_KEY": "${API_KEY}") and keep real values in your shell
#     profile or OS keychain. Rotate the exposed credential.
#   fix_hint: change_value
#   references:
#     - https://modelcontextprotocol.io/docs/concepts/transports
package boundary.mcp.secrets_in_env

import data.boundary.lib

deny contains finding if {
	some server in input.servers
	some name, value in server.env
	lib.looks_like_secret_name(name)
	literal_secret(value)
	finding := lib.finding(rego.metadata.chain(), server, {
		"server": server.name,
		"variable": name,
	})
}

deny contains finding if {
	some server in input.servers
	some header, value in server.headers
	lib.looks_like_secret_name(header)
	literal_secret(value)
	finding := lib.finding(rego.metadata.chain(), server, {
		"server": server.name,
		"header": header,
	})
}

literal_secret(value) if {
	is_string(value)
	count(value) >= 8
	not contains(value, "${")
	not startswith(value, "$")
}
