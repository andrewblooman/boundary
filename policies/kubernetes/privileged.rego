# METADATA
# title: Containers must not run privileged
# description: >
#   privileged: true disables essentially every container isolation mechanism
#   — the container gets full access to host devices and kernel capabilities.
#   It is root on the node in all but name.
# custom:
#   id: BND-K8-001
#   severity: CRITICAL
#   target: kubernetes
#   compliance:
#     soc2: [CC6.1, CC6.8]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Remove privileged: true. Grant only the specific capabilities the
#     workload needs via securityContext.capabilities.add, or use a device
#     plugin for hardware access.
#   fix_hint: remove_block
#   references:
#     - https://kubernetes.io/docs/concepts/security/pod-security-standards/
package boundary.kubernetes.privileged

import data.boundary.lib
import data.boundary.lib.k8s

deny contains finding if {
	some obj in input.objects
	k8s.is_workload(obj)
	some container in k8s.containers(obj)
	container.securityContext.privileged == true
	finding := lib.finding(rego.metadata.chain(), obj, {"container": container.name, "privileged": true})
}
