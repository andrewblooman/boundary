# METADATA
# title: Skill scripts must not touch credential stores
# description: >
#   References to ~/.ssh, ~/.aws, .env files, keychains, or browser profile
#   paths inside a skill's bundled scripts are the collection half of a
#   credential-theft payload. A skill has no business reading them.
# custom:
#   id: BND-SK-004
#   severity: CRITICAL
#   target: skills
#   compliance:
#     soc2: [CC6.1, CC6.8]
#     dora: [Art.9.4]
#     nis2: [Art.21.2j]
#     hipaa: [164.312(a)(2)(i)]
#   remediation: |
#     Remove the access. If the skill legitimately needs a credential, have
#     the user provide it explicitly through the tool's own configuration —
#     never by reading credential stores from a script.
#   fix_hint: remove_block
#   references:
#     - https://labs.snyk.io/resources/detect-tool-poisoning-mcp-server-security/
package boundary.skills.sensitive_paths

import data.boundary.lib

patterns := [
	`\.ssh/`,
	`\.aws/`,
	`\.gnupg/`,
	`\.config/gcloud`,
	`\.kube/config`,
	`\.netrc`,
	`(^|[^A-Za-z0-9_.])\.env\b`,
	`(?i)keychain`,
	`\.mozilla/firefox`,
	`(?i)Login Data`,
	`\.git-credentials`,
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
