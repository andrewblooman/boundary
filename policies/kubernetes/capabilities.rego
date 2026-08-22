# METADATA
# title: Containers must not add dangerous kernel capabilities
# description: >
#   Capabilities like SYS_ADMIN, NET_ADMIN, or ALL grant kernel-level powers
#   (mounting filesystems, rewriting routing/firewall rules, tracing other
#   processes) that make container escape practical.
# custom:
#   id: BND-K8-008
#   severity: HIGH
#   target: kubernetes
#   compliance:
#     soc2: [CC6.1, CC6.8]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Drop ALL capabilities and add back only what the workload demonstrably
#     needs (e.g. NET_BIND_SERVICE):
#     capabilities: { drop: [ALL], add: [NET_BIND_SERVICE] }.
#   fix_hint: change_value
#   references:
#     - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
package boundary.kubernetes.capabilities

import data.boundary.lib
import data.boundary.lib.k8s

dangerous := {
	"ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE",
	"DAC_OVERRIDE", "NET_RAW", "SETUID", "SETGID",
}

deny contains finding if {
	some obj in input.objects
	k8s.is_workload(obj)
	some container in k8s.containers(obj)
	added := {upper(c) | some c in object.get(container, ["securityContext", "capabilities", "add"], [])}
	bad := added & dangerous
	count(bad) > 0
	finding := lib.finding(rego.metadata.chain(), obj, {
		"container": container.name,
		"capabilities": sort([c | some c in bad]),
	})
}
