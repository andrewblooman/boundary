# METADATA
# title: Skill content must not contain obfuscated payloads
# description: >
#   Base64-decode-and-execute chains and long opaque blobs exist to hide what
#   code actually runs from both the user and scanners. In skill supply-chain
#   incidents this is the dominant delivery wrapper.
# custom:
#   id: BND-SK-005
#   severity: CRITICAL
#   target: skills
#   compliance:
#     soc2: [CC6.8, CC8.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(c)(1)]
#   remediation: |
#     Ship the code in cleartext so it can be reviewed. There is no
#     legitimate reason for a skill to decode-and-execute hidden content;
#     treat the skill as hostile until proven otherwise.
#   fix_hint: remove_block
#   references:
#     - https://labs.snyk.io/resources/detect-tool-poisoning-mcp-server-security/
package boundary.skills.obfuscation

import data.boundary.lib

exec_patterns := [
	`base64\s+(-d|--decode)[^\n]*\|\s*(ba|z|da)?sh`,
	`(?s)exec\s*\(\s*(base64|b64decode|codecs)`,
	`(?s)eval\s*\(\s*atob`,
	`echo\s+[A-Za-z0-9+/=]{40,}[^\n]*\|\s*base64`,
	`\bxxd\s+-r\b`,
	`(?i)fromCharCode`,
]

deny contains finding if {
	some script in input.scripts
	matched := [p | some p in exec_patterns; regex.match(p, script.content)]
	count(matched) > 0
	finding := lib.finding(rego.metadata.chain(), script, {
		"script": script.path,
		"patterns": matched,
	})
}

# blobs in the skill body itself (instructions asking the agent to decode)
deny contains finding if {
	regex.match(`[A-Za-z0-9+/]{120,}={0,2}`, input.body)
	regex.match(`(?i)(decode|base64|atob)`, input.body)
	finding := lib.finding(
		rego.metadata.chain(),
		{"name": object.get(input.frontmatter, "name", input.dir), "_src": {"file": input.file, "line": 0}},
		{"location": "body", "indicator": "base64 blob with decode instruction"},
	)
}
