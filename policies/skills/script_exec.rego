# METADATA
# title: Bundled skill scripts must not use dynamic code execution
# description: >
#   eval, exec, os.system, and shell=True subprocess calls in a skill's
#   scripts turn any string the agent (or an injected prompt) controls into
#   arbitrary code execution on the user's machine.
# custom:
#   id: BND-SK-003
#   severity: HIGH
#   target: skills
#   compliance:
#     soc2: [CC6.8]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(c)(1)]
#   remediation: |
#     Replace dynamic execution with explicit code paths: subprocess with an
#     argument list (shell=False), no eval/exec on constructed strings, no
#     piping model output into a shell.
#   fix_hint: change_value
#   references:
#     - https://owasp.org/www-project-agentic-skills-top-10/
package boundary.skills.script_exec

import data.boundary.lib

patterns := [
	`\beval\s*\(`,
	`\bexec\s*\(`,
	`os\.system\s*\(`,
	`shell\s*=\s*True`,
	`child_process`,
	`new\s+Function\s*\(`,
	`\bsource\s+/dev/stdin`,
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
