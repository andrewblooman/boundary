# METADATA
# title: Filesystem MCP servers must not be rooted at / or the home directory
# description: >
#   A filesystem MCP server scoped to / or ~ hands the agent — and any prompt
#   injection that reaches it — read/write access to SSH keys, cloud
#   credentials, browser profiles, and every repository on the machine.
# custom:
#   id: BND-MCP-006
#   severity: HIGH
#   target: mcp
#   compliance:
#     soc2: [CC6.1, CC6.3]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Scope the server to the narrowest project directory that works, e.g.
#     ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects/app"].
#   fix_hint: change_value
#   references:
#     - https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem
package boundary.mcp.broad_filesystem

import data.boundary.lib

broad := {"/", "~", "~/", "$HOME", "${HOME}", "/home", "/users"}

deny contains finding if {
	some server in input.servers
	filesystem_server(server)
	some arg in server.args
	normalized(arg) in broad
	finding := lib.finding(rego.metadata.chain(), server, {
		"server": server.name,
		"root": arg,
	})
}

filesystem_server(server) if {
	full := lower(concat(" ", array.concat([server.command], server.args)))
	contains(full, "filesystem")
}

normalized(arg) := lower(trim_suffix(trim_space(arg), "/")) if trim_space(arg) != "/"

normalized(arg) := "/" if trim_space(arg) == "/"
