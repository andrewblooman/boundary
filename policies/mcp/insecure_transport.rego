# METADATA
# title: Remote MCP servers must use HTTPS
# description: >
#   An http:// MCP endpoint sends tool calls, tool results, and any auth
#   headers in cleartext. On a shared network that is interception and
#   modification of the agent's entire tool traffic.
# custom:
#   id: BND-MCP-002
#   severity: HIGH
#   target: mcp
#   compliance:
#     soc2: [CC6.1, CC6.7]
#     dora: [Art.9.2]
#     nis2: [Art.21.2h]
#     hipaa: [164.312(e)(1)]
#   remediation: |
#     Change the server URL to https:// (localhost/127.0.0.1 development
#     endpoints are exempt). If the server has no TLS, front it with a
#     reverse proxy that terminates TLS.
#   fix_hint: change_value
#   references:
#     - https://modelcontextprotocol.io/docs/concepts/transports
package boundary.mcp.insecure_transport

import data.boundary.lib

deny contains finding if {
	some server in input.servers
	startswith(lower(server.url), "http://")
	not local_endpoint(server.url)
	finding := lib.finding(rego.metadata.chain(), server, {
		"server": server.name,
		"url": server.url,
	})
}

local_endpoint(url) if regex.match(`^http://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)`, lower(url))
