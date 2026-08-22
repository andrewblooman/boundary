# METADATA
# title: Dockerfiles must not embed secrets in ENV or ARG
# description: >
#   ENV and ARG values are baked into image layers and visible to anyone with
#   `docker history` or registry pull access. Build args additionally leak
#   into the build cache.
# custom:
#   id: BND-DK-003
#   severity: CRITICAL
#   target: docker
#   compliance:
#     soc2: [CC6.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2j]
#     hipaa: [164.312(a)(2)(i)]
#   remediation: |
#     Inject secrets at runtime (environment from the orchestrator's secret
#     store) or at build time with BuildKit secret mounts:
#     `RUN --mount=type=secret,id=token ...`. Rotate the exposed value.
#   fix_hint: remove_block
#   references:
#     - https://docs.docker.com/build/building/secrets/
package boundary.docker.env_secrets

import data.boundary.lib

deny contains finding if {
	some inst in input.instructions
	inst.cmd in {"ENV", "ARG"}
	some name, value in parse_pairs(inst.value)
	lib.looks_like_secret_name(name)
	count(value) >= 8
	not startswith(value, "$")
	finding := lib.finding(
		rego.metadata.chain(),
		{"name": input.file, "_src": {"file": input.file, "line": inst.line}},
		{"instruction": inst.cmd, "variable": name},
	)
}

# Handles both `ENV KEY=value KEY2=value2` and legacy `ENV KEY value`.
parse_pairs(value) := pairs if {
	contains(value, "=")
	pairs := {parts[0]: trim(concat("=", array.slice(parts, 1, count(parts))), `"'`) |
		some token in split(value, " ")
		parts := split(token, "=")
		count(parts) >= 2
		trim(concat("=", array.slice(parts, 1, count(parts))), `"'`) != ""
	}
}

parse_pairs(value) := {name: val} if {
	not contains(value, "=")
	parts := [p | some p in split(value, " "); p != ""]
	count(parts) >= 2
	name := parts[0]
	val := trim(concat(" ", array.slice(parts, 1, count(parts))), `"'`)
}
