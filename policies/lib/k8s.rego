# METADATA
# title: Kubernetes helpers
# description: >
#   Extracts pod specs and containers uniformly across workload kinds
#   (Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob) so
#   policies iterate one way regardless of the wrapping resource.
package boundary.lib.k8s

workload_kinds := {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}

is_workload(obj) if obj.kind in workload_kinds

pod_spec(obj) := obj.manifest.spec if obj.kind == "Pod"

pod_spec(obj) := obj.manifest.spec.template.spec if {
	obj.kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}
}

pod_spec(obj) := obj.manifest.spec.jobTemplate.spec.template.spec if obj.kind == "CronJob"

containers(obj) := [c |
	spec := pod_spec(obj)
	some key in {"containers", "initContainers"}
	some c in object.get(spec, key, [])
]
