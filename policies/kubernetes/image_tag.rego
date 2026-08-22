# METADATA
# title: Container images must be pinned, never :latest
# description: >
#   :latest (or an untagged image) means each node may run a different build,
#   rollbacks are impossible, and a registry compromise ships straight to
#   production on the next pull.
# custom:
#   id: BND-K8-007
#   severity: MEDIUM
#   target: kubernetes
#   compliance:
#     soc2: [CC8.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(c)(1)]
#   remediation: |
#     Pin images to an immutable version tag, ideally with a digest:
#     registry/app:1.4.2@sha256:<digest>.
#   fix_hint: change_value
#   references:
#     - https://kubernetes.io/docs/concepts/containers/images/
package boundary.kubernetes.image_tag

import data.boundary.lib
import data.boundary.lib.k8s

deny contains finding if {
	some obj in input.objects
	k8s.is_workload(obj)
	some container in k8s.containers(obj)
	image := object.get(container, "image", "")
	unpinned(image)
	finding := lib.finding(rego.metadata.chain(), obj, {
		"container": container.name,
		"image": image,
	})
}

unpinned(image) if endswith(image, ":latest")

unpinned(image) if {
	not contains(image, "@")

	# a colon may belong to a registry port (host:5000/app), so check the last
	# path segment for a tag
	segments := split(image, "/")
	not contains(segments[count(segments) - 1], ":")
}
