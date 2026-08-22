# METADATA
# title: Containers must set allowPrivilegeEscalation to false
# description: >
#   When allowPrivilegeEscalation is not explicitly false, a process can gain
#   more privileges than its parent via setuid binaries or file capabilities
#   — the standard first step in container breakout chains.
# custom:
#   id: BND-K8-002
#   severity: HIGH
#   target: kubernetes
#   compliance:
#     soc2: [CC6.1, CC6.8]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Set securityContext.allowPrivilegeEscalation: false on every container
#     (required by the "restricted" Pod Security Standard).
#   fix_hint: add_block
#   references:
#     - https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted
package boundary.kubernetes.privilege_escalation

import data.boundary.lib
import data.boundary.lib.k8s

deny contains finding if {
	some obj in input.objects
	k8s.is_workload(obj)
	some container in k8s.containers(obj)
	object.get(container, ["securityContext", "allowPrivilegeEscalation"], true) != false
	finding := lib.finding(rego.metadata.chain(), obj, {
		"container": container.name,
		"allowPrivilegeEscalation": "not disabled",
	})
}
