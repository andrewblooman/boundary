# METADATA
# title: Bundled skill scripts making network calls need review
# description: >
#   A script shipped inside a skill runs with the user's credentials and
#   filesystem. Network calls from such scripts are the exfiltration channel
#   in every published skill-poisoning campaign — legitimate uses exist, but
#   each one should be knowingly accepted.
# custom:
#   id: BND-SK-002
#   severity: MEDIUM
#   target: skills
#   compliance:
#     soc2: [CC6.7, CC6.8]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(e)(1)]
#   remediation: |
#     Review each network call: confirm the destination is expected,
#     documented in the skill's description, and uses HTTPS. Remove any call
#     the skill does not need.
#   fix_hint: review
#   references:
#     - https://labs.snyk.io/resources/detect-tool-poisoning-mcp-server-security/
package boundary.skills.script_network

import data.boundary.lib

patterns := [
	`\bcurl\b`,
	`\bwget\b`,
	`requests\.(get|post|put|delete|request)`,
	`urllib\.request`,
	`\bfetch\s*\(`,
	`http\.(get|request)`,
	`XMLHttpRequest`,
	`\bInvoke-WebRequest\b`,
]

deny contains finding if {
	some script in input.scripts
	matched := [p | some p in patterns; regex.match(p, script.content)]
	count(matched) > 0
	finding := lib.finding(rego.metadata.chain(), script, {
		"script": script.path,
		"patterns": matched,
	})
}
