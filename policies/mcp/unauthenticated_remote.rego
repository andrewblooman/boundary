# METADATA
# title: Remote MCP servers should declare authentication
# description: >
#   A remote MCP server configured with no auth headers either is open to
#   anyone (an unauthenticated tool backend the agent will happily call) or
#   authenticates out-of-band in a way this config cannot audit. Both deserve
#   review.
# custom:
#   id: BND-MCP-003
#   severity: MEDIUM
#   target: mcp
#   compliance:
#     soc2: [CC6.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2j]
#     hipaa: [164.312(d)]
#   remediation: |
#     Add an Authorization header referencing an environment variable, or use
#     an OAuth-capable MCP client flow. If the endpoint is intentionally
#     public and read-only, document that where the config lives.
#   fix_hint: review
#   references:
#     - https://modelcontextprotocol.io/specification/draft/basic/authorization
package boundary.mcp.unauthenticated_remote

import data.boundary.lib

deny contains finding if {
	some server in input.servers
	server.url != ""
	not local_endpoint(server.url)
	not has_auth(server)
	finding := lib.finding(rego.metadata.chain(), server, {
		"server": server.name,
		"url": server.url,
		"headers": "none",
	})
}

has_auth(server) if {
	some header, _ in server.headers
	regex.match(`(?i)(authorization|api[_-]?key|token|secret)`, header)
}

local_endpoint(url) if regex.match(`^https?://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)`, lower(url))
