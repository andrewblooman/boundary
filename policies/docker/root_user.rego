# METADATA
# title: Containers must not run as root
# description: >
#   Without a USER instruction (or with a final USER of root) the container
#   process runs as uid 0. A container escape or dependency compromise then
#   starts with root privileges on the host's kernel.
# custom:
#   id: BND-DK-001
#   severity: HIGH
#   target: docker
#   compliance:
#     soc2: [CC6.1, CC6.8]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Create a dedicated user in the image and switch to it as the last USER
#     instruction, e.g. `RUN useradd -r app` followed by `USER app`
#     (or `USER 10001` for a numeric, non-root uid).
#   fix_hint: add_block
#   references:
#     - https://docs.docker.com/build/building/best-practices/#user
package boundary.docker.root_user

import data.boundary.lib

# Only the final build stage ships, so only USER instructions after the last
# FROM count.
deny contains finding if {
	count(users) == 0
	finding := lib.finding(rego.metadata.chain(), src(last_from.line), {"user": "not set (root)"})
}

deny contains finding if {
	count(users) > 0
	last := users[count(users) - 1]
	is_root(last.value)
	finding := lib.finding(rego.metadata.chain(), src(last.line), {"user": last.value})
}

froms := [i | some i in input.instructions; i.cmd == "FROM"]

last_from := froms[count(froms) - 1]

users := [i |
	some i in input.instructions
	i.cmd == "USER"
	i.line > last_from.line
]

is_root(value) if lower(trim_space(value)) == "root"

is_root(value) if trim_space(value) == "0"

src(line) := {"name": input.file, "_src": {"file": input.file, "line": line}}
