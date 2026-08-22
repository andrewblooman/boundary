# METADATA
# title: Workloads must not mount hostPath volumes
# description: >
#   hostPath mounts pierce container isolation: with the wrong path
#   (/var/run/docker.sock, /, /etc) a compromised pod reads or controls the
#   node. They also break scheduling portability.
# custom:
#   id: BND-K8-004
#   severity: HIGH
#   target: kubernetes
#   compliance:
#     soc2: [CC6.1, CC6.8]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Use persistentVolumeClaims, configMaps, secrets, or emptyDir instead.
#     If a hostPath is unavoidable (node agents), mount it readOnly, scope it
#     to the narrowest path, and gate it with admission policy.
#   fix_hint: remove_block
#   references:
#     - https://kubernetes.io/docs/concepts/storage/volumes/#hostpath
package boundary.kubernetes.host_path

import data.boundary.lib
import data.boundary.lib.k8s

deny contains finding if {
	some obj in input.objects
	k8s.is_workload(obj)
	some volume in object.get(k8s.pod_spec(obj), "volumes", [])
	volume.hostPath
	finding := lib.finding(rego.metadata.chain(), obj, {
		"volume": object.get(volume, "name", ""),
		"hostPath": object.get(volume.hostPath, "path", ""),
	})
}
