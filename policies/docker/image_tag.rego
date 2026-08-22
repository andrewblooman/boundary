# METADATA
# title: Base images must be pinned to a specific tag
# description: >
#   FROM image:latest (or an untagged FROM) makes builds non-reproducible and
#   silently pulls whatever the registry serves — including a compromised
#   image after a registry or upstream takeover.
# custom:
#   id: BND-DK-002
#   severity: MEDIUM
#   target: docker
#   compliance:
#     soc2: [CC8.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(c)(1)]
#   remediation: |
#     Pin the base image to a specific version tag (python:3.14-slim) and,
#     for supply-chain integrity, to a digest:
#     python:3.14-slim@sha256:<digest>.
#   fix_hint: change_value
#   references:
#     - https://docs.docker.com/build/building/best-practices/#pin-base-image-versions
package boundary.docker.image_tag

import data.boundary.lib

deny contains finding if {
	some inst in input.instructions
	inst.cmd == "FROM"
	image := image_ref(inst.value)
	not exempt(image)
	unpinned(image)
	finding := lib.finding(
		rego.metadata.chain(),
		{"name": input.file, "_src": {"file": input.file, "line": inst.line}},
		{"image": image},
	)
}

# strip flags (--platform=...) and any trailing "AS stage" alias
image_ref(value) := ref if {
	parts := [p | some p in split(value, " "); p != ""; not startswith(p, "--")]
	ref := lower(parts[0])
}

exempt("scratch")

exempt(image) if image in {lower(s) | some s in input.stages} # copy from earlier stage

unpinned(image) if contains(image, ":latest")

unpinned(image) if {
	not contains(image, ":")
	not contains(image, "@")
}
