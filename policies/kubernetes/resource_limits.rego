# METADATA
# title: Containers must declare CPU and memory limits
# description: >
#   Without limits one runaway or maliciously-driven container can starve
#   every other workload on the node — a self-inflicted denial of service
#   and a resilience finding under every operational framework.
# custom:
#   id: BND-K8-006
#   severity: MEDIUM
#   target: kubernetes
#   compliance:
#     soc2: [A1.1, CC6.8]
#     dora: [Art.10]
#     nis2: [Art.21.2c]
#     hipaa: []
#   remediation: |
#     Add resources.requests and resources.limits (memory always; CPU limit
#     per your throttling policy) to every container, or enforce namespace
#     LimitRange defaults.
#   fix_hint: add_block
#   references:
#     - https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/
package boundary.kubernetes.resource_limits

import data.boundary.lib
import data.boundary.lib.k8s

deny contains finding if {
	some obj in input.objects
	k8s.is_workload(obj)
	some container in k8s.containers(obj)
	missing := [r |
		some r in ["cpu", "memory"]
		not object.get(container, ["resources", "limits", r], false)
	]
	count(missing) > 0
	finding := lib.finding(rego.metadata.chain(), obj, {
		"container": container.name,
		"missing_limits": missing,
	})
}
