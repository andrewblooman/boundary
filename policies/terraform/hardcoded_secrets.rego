# METADATA
# title: Terraform must not contain hardcoded credentials
# description: >
#   Secrets committed in .tf files end up in git history, state files, and
#   plan output forever. Rotating them requires rewriting history; assume any
#   committed credential is compromised.
# custom:
#   id: BND-TF-008
#   severity: CRITICAL
#   target: terraform
#   compliance:
#     soc2: [CC6.1]
#     dora: [Art.9.4]
#     nis2: [Art.21.2j]
#     hipaa: [164.312(a)(2)(i)]
#   remediation: |
#     Move the value to a secret manager (AWS Secrets Manager, SSM Parameter
#     Store, Vault) and reference it via a data source, or pass it as a
#     sensitive variable supplied at apply time. Rotate the exposed credential.
#   fix_hint: change_value
#   references:
#     - https://developer.hashicorp.com/terraform/tutorials/configuration-language/sensitive-variables
package boundary.terraform.hardcoded_secrets

import data.boundary.lib

deny contains finding if {
	some res in input.resources
	some attr, value in res.values
	lib.looks_like_secret_name(attr)
	lib.is_literal_secret(value)
	not ignorable(attr, value)
	finding := lib.finding(rego.metadata.chain(), res, {
		"attribute": attr,
		"value_preview": substring(value, 0, 4),
	})
}

# ARNs, key ids, and secret *names* are references, not secret material.
ignorable(attr, _) if regex.match(`(?i)(arn|_id$|_name$|_alias$|key_id)`, attr)

ignorable(_, value) if startswith(value, "arn:")

ignorable(_, value) if count(value) < 8
