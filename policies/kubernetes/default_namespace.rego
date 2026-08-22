# METADATA
# title: Workloads must not deploy to the default namespace
# description: >
#   The default namespace has no tailored RBAC, network policies, or resource
#   quotas, and mixes unrelated workloads into one blast radius. Explicit
#   namespaces are the unit of isolation and least privilege in Kubernetes.
# custom:
#   id: BND-K8-009
#   severity: LOW
#   target: kubernetes
#   compliance:
#     soc2: [CC6.3]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Set metadata.namespace to a purpose-specific namespace with its own
#     RBAC bindings, NetworkPolicy, and ResourceQuota.
#   fix_hint: change_value
#   references:
#     - https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/
package boundary.kubernetes.default_namespace

import data.boundary.lib
import data.boundary.lib.k8s

deny contains finding if {
	some obj in input.objects
	k8s.is_workload(obj)
	namespace := object.get(obj.manifest, ["metadata", "namespace"], "default")
	namespace == "default"
	finding := lib.finding(rego.metadata.chain(), obj, {"namespace": namespace})
}
