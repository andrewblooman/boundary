# METADATA
# title: Skills must declare an honest name and description
# description: >
#   A skill with no name or description cannot be meaningfully reviewed or
#   audited, and description-less skills are over-represented among malicious
#   uploads. The description is the contract the user approves.
# custom:
#   id: BND-SK-006
#   severity: LOW
#   target: skills
#   compliance:
#     soc2: [CC8.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: []
#   remediation: |
#     Add frontmatter with a meaningful name and a description that states
#     what the skill does, what it reads, and anything it sends off-machine.
#   fix_hint: add_block
#   references:
#     - https://code.claude.com/docs/en/skills
package boundary.skills.manifest_hygiene

import data.boundary.lib

deny contains finding if {
	missing := [field |
		some field in ["name", "description"]
		trim_space(object.get(input.frontmatter, field, "")) == ""
	]
	count(missing) > 0
	finding := lib.finding(
		rego.metadata.chain(),
		{"name": object.get(input.frontmatter, "name", input.dir), "_src": {"file": input.file, "line": 1}},
		{"missing_frontmatter": missing},
	)
}
