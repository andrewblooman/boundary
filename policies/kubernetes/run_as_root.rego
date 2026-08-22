# METADATA
# title: Workloads must run as a non-root user
# description: >
#   Without runAsNonRoot (or with runAsUser 0) the container may run as uid 0.
#   Root inside the container plus any kernel or runtime bug equals root on
#   the node.
# custom:
#   id: BND-K8-003
#   severity: HIGH
#   target: kubernetes
#   compliance:
#     soc2: [CC6.1, CC6.8]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Set securityContext.runAsNonRoot: true (pod or container level) and a
#     numeric runAsUser >= 1000. The image must contain a matching non-root
#     user.
#   fix_hint: add_block
#   references:
#     - https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
package boundary.kubernetes.run_as_root

import data.boundary.lib
import data.boundary.lib.k8s

deny contains finding if {
	some obj in input.objects
	k8s.is_workload(obj)
	some container in k8s.containers(obj)
	not non_root(obj, container)
	finding := lib.finding(rego.metadata.chain(), obj, {
		"container": container.name,
		"runAsNonRoot": "not enforced",
	})
}

non_root(obj, container) if {
	container.securityContext.runAsNonRoot == true
	not runs_as_zero(obj, container)
}

non_root(obj, container) if {
	k8s.pod_spec(obj).securityContext.runAsNonRoot == true
	not runs_as_zero(obj, container)
}

runs_as_zero(_, container) if container.securityContext.runAsUser == 0

runs_as_zero(obj, _) if k8s.pod_spec(obj).securityContext.runAsUser == 0
