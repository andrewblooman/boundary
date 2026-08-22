# METADATA
# title: MCP servers launched via npx/uvx must pin a version
# description: >
#   `npx -y some-mcp-server` fetches and executes the newest published version
#   on every client start. One malicious release upstream — the ToxicSkills
#   pattern — becomes code execution on every machine using the config.
# custom:
#   id: BND-MCP-005
#   severity: HIGH
#   target: mcp
#   compliance:
#     soc2: [CC8.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(c)(1)]
#   remediation: |
#     Pin the package version in the args (e.g. `npx -y
#     @scope/server@1.2.3`, `uvx package==1.2.3`), or install the server
#     locally and point command at the installed binary.
#   fix_hint: change_value
#   references:
#     - https://labs.snyk.io/resources/detect-tool-poisoning-mcp-server-security/
package boundary.mcp.unpinned_package

import data.boundary.lib

runners := {"npx", "uvx", "pnpx", "bunx"}

deny contains finding if {
	some server in input.servers
	base_command(server.command) in runners
	pkg := package_arg(server.args)
	not pinned(pkg)
	finding := lib.finding(rego.metadata.chain(), server, {
		"server": server.name,
		"package": pkg,
	})
}

base_command(command) := parts[count(parts) - 1] if {
	parts := split(command, "/")
}

# first arg that is not a flag is the package reference
package_arg(args) := [a | some a in args; not startswith(a, "-")][0]

pinned(pkg) if {
	# @scope/name@1.2.3 or name@1.2.3 — an @ after the first character
	some i in numbers.range(1, count(pkg) - 1)
	substring(pkg, i, 1) == "@"
}

pinned(pkg) if contains(pkg, "==") # uvx style
