# METADATA
# title: Skill text must not contain instruction-hijacking phrasing
# description: >
#   Phrases like "ignore previous instructions", "do not tell the user", or
#   "without asking" inside a skill's description or body are the signature
#   of prompt-injection / tool-poisoning payloads: they steer the agent
#   against its user while looking like documentation.
# custom:
#   id: BND-SK-001
#   severity: CRITICAL
#   target: skills
#   compliance:
#     soc2: [CC6.8]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(c)(1)]
#   remediation: |
#     Remove the hijacking language. Legitimate skills describe what to do,
#     not what to hide; anything a skill needs the user not to see is a
#     reason to reject the skill entirely.
#   fix_hint: remove_block
#   references:
#     - https://labs.snyk.io/resources/detect-tool-poisoning-mcp-server-security/
package boundary.skills.injection_phrasing

import data.boundary.lib

patterns := [
	`(?i)ignore (all )?(previous|prior|above) (instructions|prompts|rules)`,
	`(?i)do("| )?n[o']t (tell|show|inform|mention|reveal)( this)?( to)? the user`,
	`(?i)without (asking|telling|informing|notifying)( the)? (the )?user`,
	`(?i)(hide|conceal) (this|these|the following) (from|instruction)`,
	`(?i)secretly`,
	`(?i)(exfiltrate|send) .{0,40}(credentials|secrets|keys|tokens)`,
	`(?i)do not (log|report|disclose)`,
]

deny contains finding if {
	some source, text in {"description": description_text, "body": input.body}
	some pattern in patterns
	regex.match(pattern, text)
	finding := lib.finding(
		rego.metadata.chain(),
		{"name": skill_name, "_src": {"file": input.file, "line": 0}},
		{"location": source, "pattern": pattern},
	)
}

description_text := object.get(input.frontmatter, "description", "")

skill_name := object.get(input.frontmatter, "name", input.dir)
