package boundary.terraform_test

import data.boundary.terraform

res(rtype, name, values) := {
	"type": rtype, "name": name, "address": sprintf("%s.%s", [rtype, name]),
	"mode": "managed", "values": values,
	"_src": {"file": "main.tf", "line": 1},
}

tf(resources) := {"kind": "terraform", "source": "hcl", "resources": resources}

tf_config(provider_configs, backends, version) := {
	"kind": "terraform",
	"source": "hcl",
	"resources": [],
	"providers": provider_configs,
	"terraform": {
		"configurations": [{
			"required_version": version,
			"backends": backends,
			"is_root": true,
			"_src": {"file": "providers.tf", "line": 1, "name": "terraform"},
		}],
	},
}

test_s3_encryption_flags_bare_bucket if {
	count(terraform.s3_encryption.deny) == 1 with input as tf([res("aws_s3_bucket", "b", {})])
}

test_s3_encryption_accepts_sse_resource if {
	count(terraform.s3_encryption.deny) == 0 with input as tf([
		res("aws_s3_bucket", "b", {}),
		res("aws_s3_bucket_server_side_encryption_configuration", "b", {"bucket": "${aws_s3_bucket.b.id}"}),
	])
}

test_public_acl_flagged if {
	count(terraform.s3_public_acl.deny) == 1 with input as tf([res("aws_s3_bucket", "b", {"acl": "public-read"})])
}

test_private_acl_ok if {
	count(terraform.s3_public_acl.deny) == 0 with input as tf([res("aws_s3_bucket", "b", {"acl": "private"})])
}

test_open_ingress_flagged if {
	count(terraform.sg_open_ingress.deny) == 1 with input as tf([res(
		"aws_security_group", "sg",
		{"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]},
	)])
}

test_scoped_ingress_ok if {
	count(terraform.sg_open_ingress.deny) == 0 with input as tf([res(
		"aws_security_group", "sg",
		{"ingress": [{"from_port": 443, "to_port": 443, "cidr_blocks": ["10.0.0.0/8"]}]},
	)])
}

test_iam_wildcard_flagged if {
	count(terraform.iam_wildcard.deny) == 1 with input as tf([res(
		"aws_iam_policy", "p",
		{"policy": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
	)])
}

test_iam_scoped_ok if {
	count(terraform.iam_wildcard.deny) == 0 with input as tf([res(
		"aws_iam_policy", "p",
		{"policy": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`},
	)])
}

test_unencrypted_ebs_flagged if {
	count(terraform.ebs_encryption.deny) == 1 with input as tf([res("aws_ebs_volume", "v", {"size": 10})])
}

test_encrypted_ebs_ok if {
	count(terraform.ebs_encryption.deny) == 0 with input as tf([res("aws_ebs_volume", "v", {"encrypted": true})])
}

test_rds_unencrypted_flagged if {
	count(terraform.rds_encryption.deny) == 1 with input as tf([res("aws_db_instance", "db", {})])
}

test_rds_encrypted_ok if {
	count(terraform.rds_encryption.deny) == 0 with input as tf([res("aws_db_instance", "db", {"storage_encrypted": true})])
}

test_public_db_flagged if {
	count(terraform.db_public_access.deny) == 1 with input as tf([res("aws_db_instance", "db", {"publicly_accessible": true})])
}

test_hardcoded_secret_flagged if {
	count(terraform.hardcoded_secrets.deny) == 1 with input as tf([res("aws_db_instance", "db", {"password": "FAKE-PASSWORD-FOR-TESTS"})])
}

test_variable_secret_ok if {
	count(terraform.hardcoded_secrets.deny) == 0 with input as tf([res("aws_db_instance", "db", {"password": "${var.db_password}"})])
}

test_secret_arn_ok if {
	count(terraform.hardcoded_secrets.deny) == 0 with input as tf([res(
		"aws_ecs_task_definition", "t",
		{"secret_arn": "arn:aws:secretsmanager:eu-west-2:123:secret:x"},
	)])
}

test_kms_no_rotation_flagged if {
	count(terraform.kms_rotation.deny) == 1 with input as tf([res("aws_kms_key", "k", {})])
}

test_kms_rotation_ok if {
	count(terraform.kms_rotation.deny) == 0 with input as tf([res("aws_kms_key", "k", {"enable_key_rotation": true})])
}

test_http_listener_flagged if {
	count(terraform.lb_insecure_listener.deny) == 1 with input as tf([res(
		"aws_lb_listener", "l",
		{"protocol": "HTTP", "default_action": [{"type": "forward"}]},
	)])
}

test_http_redirect_ok if {
	count(terraform.lb_insecure_listener.deny) == 0 with input as tf([res(
		"aws_lb_listener", "l",
		{"protocol": "HTTP", "default_action": [{"type": "redirect"}]},
	)])
}

test_finding_shape_carries_metadata if {
	some f in terraform.kms_rotation.deny with input as tf([res("aws_kms_key", "k", {})])
	f.id == "BND-TF-009"
	f.severity == "MEDIUM"
	f.compliance.soc2[0] == "CC6.1"
	f.target.file == "main.tf"
	f.fix_hint == "add_block"
}

# --- GCP policies ---

test_sql_public_ip_flagged_when_true if {
	count(terraform.gcp_sql_public_ip.deny) == 1 with input as tf([res(
		"google_sql_database_instance", "db",
		{"settings": [{"ip_configuration": [{"ipv4_enabled": true}]}]},
	)])
}

test_sql_public_ip_flagged_when_block_missing if {
	count(terraform.gcp_sql_public_ip.deny) == 1 with input as tf([res(
		"google_sql_database_instance", "db",
		{"settings": [{}]},
	)])
}

test_sql_private_ip_ok if {
	count(terraform.gcp_sql_public_ip.deny) == 0 with input as tf([res(
		"google_sql_database_instance", "db",
		{"settings": [{"ip_configuration": [{"ipv4_enabled": false}]}]},
	)])
}

test_sql_no_ssl_flagged if {
	count(terraform.gcp_sql_require_ssl.deny) == 1 with input as tf([res(
		"google_sql_database_instance", "db",
		{"settings": [{"ip_configuration": [{"ssl_mode": "ALLOW_UNENCRYPTED_AND_ENCRYPTED"}]}]},
	)])
}

test_sql_no_ssl_flagged_when_block_missing if {
	count(terraform.gcp_sql_require_ssl.deny) == 1 with input as tf([res(
		"google_sql_database_instance", "db",
		{"settings": [{}]},
	)])
}

test_sql_encrypted_only_ok if {
	count(terraform.gcp_sql_require_ssl.deny) == 0 with input as tf([res(
		"google_sql_database_instance", "db",
		{"settings": [{"ip_configuration": [{"ssl_mode": "ENCRYPTED_ONLY"}]}]},
	)])
}

test_firewall_open_ingress_flagged if {
	count(terraform.gcp_firewall_open_ingress.deny) == 1 with input as tf([res(
		"google_compute_firewall", "fw",
		{"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp", "ports": ["22"]}]},
	)])
}

test_firewall_scoped_ingress_ok if {
	count(terraform.gcp_firewall_open_ingress.deny) == 0 with input as tf([res(
		"google_compute_firewall", "fw",
		{"direction": "INGRESS", "source_ranges": ["10.0.0.0/24"], "allow": [{"protocol": "tcp", "ports": ["22"]}]},
	)])
}

test_firewall_deny_rule_open_ok if {
	count(terraform.gcp_firewall_open_ingress.deny) == 0 with input as tf([res(
		"google_compute_firewall", "fw",
		{"direction": "INGRESS", "source_ranges": ["0.0.0.0/0"], "deny": [{"protocol": "all"}]},
	)])
}

test_iam_member_public_flagged if {
	count(terraform.gcp_iam_public_member.deny) == 1 with input as tf([res(
		"google_storage_bucket_iam_member", "m",
		{"member": "allUsers", "role": "roles/storage.objectViewer"},
	)])
}

test_iam_binding_public_flagged if {
	count(terraform.gcp_iam_public_member.deny) == 1 with input as tf([res(
		"google_project_iam_binding", "b",
		{"members": ["allAuthenticatedUsers"], "role": "roles/viewer"},
	)])
}

test_iam_member_scoped_ok if {
	count(terraform.gcp_iam_public_member.deny) == 0 with input as tf([res(
		"google_project_iam_member", "m",
		{"member": "serviceAccount:app@proj.iam.gserviceaccount.com", "role": "roles/logging.logWriter"},
	)])
}

test_iam_primitive_owner_flagged if {
	count(terraform.gcp_iam_primitive_role.deny) == 1 with input as tf([res(
		"google_project_iam_member", "m",
		{"member": "user:dev@example.com", "role": "roles/owner"},
	)])
}

test_iam_scoped_role_ok if {
	count(terraform.gcp_iam_primitive_role.deny) == 0 with input as tf([res(
		"google_project_iam_member", "m",
		{"member": "serviceAccount:app@proj.iam.gserviceaccount.com", "role": "roles/cloudsql.client"},
	)])
}

test_service_account_key_flagged if {
	count(terraform.gcp_service_account_key.deny) == 1 with input as tf([res(
		"google_service_account_key", "k",
		{"service_account_id": "app-sa"},
	)])
}

test_no_service_account_key_ok if {
	count(terraform.gcp_service_account_key.deny) == 0 with input as tf([res("google_service_account", "sa", {})])
}

test_aws_default_tags_flagged if {
	count(terraform.aws_default_tags.deny) == 1 with input as tf_config(
		[
			{"name": "aws", "values": {}, "_src": {"file": "providers.tf", "line": 1}},
		],
		[], ">= 1.15",
	)
}

test_aws_default_tags_ok if {
	count(terraform.aws_default_tags.deny) == 0 with input as tf_config(
		[
			{
				"name": "aws", "values": {"default_tags": [{"tags": {"environment": "prod"}}]},
				"_src": {"file": "providers.tf", "line": 1},
			},
		],
		[], ">= 1.15",
	)
}

test_google_default_labels_flagged if {
	count(terraform.google_default_labels.deny) == 1 with input as tf_config(
		[
			{"name": "google", "values": {}, "_src": {"file": "providers.tf", "line": 1}},
		],
		[], ">= 1.15",
	)
}

test_google_default_labels_ok if {
	count(terraform.google_default_labels.deny) == 0 with input as tf_config(
		[
			{
				"name": "google", "values": {"default_labels": {"environment": "prod"}},
				"_src": {"file": "providers.tf", "line": 1},
			},
		],
		[], ">= 1.15",
	)
}

test_remote_backend_flagged_when_missing if {
	count(terraform.remote_backend.deny) == 1 with input as tf_config([], [], ">= 1.15")
}

test_remote_backend_accepts_gcs if {
	count(terraform.remote_backend.deny) == 0 with input as tf_config(
		[], [
			{"name": "gcs", "values": {}, "_src": {"file": "providers.tf", "line": 1}},
		],
		">= 1.15",
	)
}

test_remote_backend_ignores_child_modules if {
	count(terraform.remote_backend.deny) == 0 with input as {
		"kind": "terraform",
		"source": "hcl",
		"resources": [],
		"providers": [],
		"terraform": {
			"configurations": [{
				"required_version": ">= 1.15",
				"backends": [],
				"is_root": false,
				"_src": {"file": "modules/service/versions.tf", "line": 1},
			}],
		},
	}
}

test_s3_backend_locking_flags_dynamodb_and_missing_lock_file if {
	count(terraform.s3_backend_locking.deny) == 2 with input as tf_config(
		[], [
			{
				"name": "s3", "values": {"dynamodb_table": "locks"},
				"_src": {"file": "providers.tf", "line": 1},
			},
		],
		">= 1.15",
	)
}

test_s3_backend_locking_accepts_lock_file if {
	count(terraform.s3_backend_locking.deny) == 0 with input as tf_config(
		[], [
			{
				"name": "s3", "values": {"use_lockfile": true},
				"_src": {"file": "providers.tf", "line": 1},
			},
		],
		">= 1.15",
	)
}

test_minimum_version_flags_older_version if {
	count(terraform.minimum_version.deny) == 1 with input as tf_config([], [], ">= 1.14")
}

test_minimum_version_accepts_required_lower_bound if {
	count(terraform.minimum_version.deny) == 0 with input as tf_config([], [], ">= 1.15, < 2.0")
}

test_minimum_version_accepts_strict_greater_than if {
	count(terraform.minimum_version.deny) == 0 with input as tf_config([], [], "> 1.15")
}

test_minimum_version_accepts_exact_version if {
	count(terraform.minimum_version.deny) == 0 with input as tf_config([], [], "== 1.15")
}
