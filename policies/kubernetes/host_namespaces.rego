# METADATA
# title: Workloads must not share host namespaces
# description: >
#   hostNetwork, hostPID, and hostIPC collapse the isolation boundary between
#   pod and node: the pod sees node network interfaces, every process on the
#   host, or shared memory segments of other workloads.
# custom:
#   id: BND-K8-005
#   severity: HIGH
#   target: kubernetes
#   compliance:
#     soc2: [CC6.1, CC6.6]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Remove hostNetwork/hostPID/hostIPC. Expose services through Services and
#     Ingress; for observability agents that genuinely need host visibility,
#     isolate them in a dedicated, admission-controlled namespace.
#   fix_hint: remove_block
#   references:
#     - https://kubernetes.io/docs/concepts/security/pod-security-standards/#baseline
package boundary.kubernetes.host_namespaces

import data.boundary.lib
import data.boundary.lib.k8s

deny contains finding if {
	some obj in input.objects
	k8s.is_workload(obj)
	some flag in {"hostNetwork", "hostPID", "hostIPC"}
	k8s.pod_spec(obj)[flag] == true
	finding := lib.finding(rego.metadata.chain(), obj, {"shared": flag})
}
