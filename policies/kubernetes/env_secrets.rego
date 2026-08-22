# METADATA
# title: Manifests must not contain literal secrets in env vars
# description: >
#   A credential written as a literal env value lives in git, in kubectl
#   output, and in every cluster backup. Anyone with read access to the
#   manifest or the API object has the secret.
# custom:
#   id: BND-K8-010
#   severity: CRITICAL
#   target: kubernetes
#   compliance:
#     soc2: [CC6.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2j]
#     hipaa: [164.312(a)(2)(i)]
#   remediation: |
#     Reference a Secret instead: valueFrom.secretKeyRef (backed by an
#     external secret store via External Secrets Operator or CSI driver).
#     Rotate the exposed credential.
#   fix_hint: change_value
#   references:
#     - https://kubernetes.io/docs/concepts/configuration/secret/
package boundary.kubernetes.env_secrets

import data.boundary.lib
import data.boundary.lib.k8s

deny contains finding if {
	some obj in input.objects
	k8s.is_workload(obj)
	some container in k8s.containers(obj)
	some env in object.get(container, "env", [])
	lib.looks_like_secret_name(object.get(env, "name", ""))
	value := object.get(env, "value", "")
	is_string(value)
	count(value) >= 8
	not startswith(value, "$")
	finding := lib.finding(rego.metadata.chain(), obj, {
		"container": container.name,
		"variable": env.name,
	})
}
