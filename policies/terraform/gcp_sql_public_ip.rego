# METADATA
# title: Cloud SQL instances must not have a public IP
# description: >
#   Google Cloud SQL assigns a public IPv4 address by default unless
#   ip_configuration explicitly disables it. A publicly reachable database is
#   one leaked credential or authorized-networks mistake away from exposure —
#   private IP (reached over VPC peering or a connector) removes the public
#   attack surface entirely.
# custom:
#   id: BND-TF-011
#   severity: CRITICAL
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.6]
#     dora: [Art.9.3]
#     nis2: [Art.21.2e]
#     hipaa: [164.312(e)(1)]
#   remediation: |
#     Set ip_configuration.ipv4_enabled = false and connect over
#     private_network (Private Service Access) or the Cloud SQL Auth Proxy /
#     connector instead. If a public IP is genuinely required, restrict it
#     with authorized_networks rather than leaving it open.
#   fix_hint: change_value
#   references:
#     - https://cloud.google.com/sql/docs/postgres/configure-private-ip
package boundary.terraform.gcp_sql_public_ip

import data.boundary.lib

deny contains finding if {
	some res in input.resources
	res.type == "google_sql_database_instance"
	some setting in lib.as_array(object.get(res.values, "settings", []))
	some ipcfg in lib.as_array(object.get(setting, "ip_configuration", []))
	lib.is_true(object.get(ipcfg, "ipv4_enabled", true))
	finding := lib.finding(rego.metadata.chain(), res, {"ipv4_enabled": true})
}

# ip_configuration itself defaults to a public IP when the block is omitted
# entirely, not just when ipv4_enabled is left unset inside it.
deny contains finding if {
	some res in input.resources
	res.type == "google_sql_database_instance"
	some setting in lib.as_array(object.get(res.values, "settings", []))
	count(lib.as_array(object.get(setting, "ip_configuration", []))) == 0
	finding := lib.finding(rego.metadata.chain(), res, {"ip_configuration": "not set (defaults to public IP)"})
}
