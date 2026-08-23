# METADATA
# title: Cloud SQL instances must require encrypted connections
# description: >
#   The default ssl_mode (ALLOW_UNENCRYPTED_AND_ENCRYPTED) lets clients
#   connect in plaintext, so credentials and query results can be read by
#   anything on the network path. Requiring encryption costs nothing at
#   connect time and closes off passive interception.
# custom:
#   id: BND-TF-012
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.7]
#     dora: [Art.9.2]
#     nis2: [Art.21.2h]
#     hipaa: [164.312(e)(1)]
#   remediation: |
#     Set ip_configuration.ssl_mode to ENCRYPTED_ONLY or
#     TRUSTED_CLIENT_CERTIFICATE_REQUIRED. On older provider versions without
#     ssl_mode, set the legacy require_ssl = true instead.
#   fix_hint: change_value
#   references:
#     - https://cloud.google.com/sql/docs/postgres/configure-ssl-instance
package boundary.terraform.gcp_sql_require_ssl

import data.boundary.lib

secure_ssl_modes := {"ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"}

deny contains finding if {
	some res in input.resources
	res.type == "google_sql_database_instance"
	some setting in lib.as_array(object.get(res.values, "settings", []))
	some ipcfg in lib.as_array(object.get(setting, "ip_configuration", []))
	mode := object.get(ipcfg, "ssl_mode", "")
	not mode in secure_ssl_modes
	not lib.is_true(object.get(ipcfg, "require_ssl", false))
	finding := lib.finding(rego.metadata.chain(), res, {"ssl_mode": mode})
}

# ip_configuration itself defaults to allowing plaintext connections when the
# block is omitted entirely, not just when ssl_mode is left unset inside it.
deny contains finding if {
	some res in input.resources
	res.type == "google_sql_database_instance"
	some setting in lib.as_array(object.get(res.values, "settings", []))
	count(lib.as_array(object.get(setting, "ip_configuration", []))) == 0
	finding := lib.finding(rego.metadata.chain(), res, {"ip_configuration": "not set (defaults to unencrypted allowed)"})
}
