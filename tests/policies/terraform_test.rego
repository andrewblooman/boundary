package boundary.terraform_test

import data.boundary.terraform

res(rtype, name, values) := {
	"type": rtype, "name": name, "address": sprintf("%s.%s", [rtype, name]),
	"mode": "managed", "values": values,
	"_src": {"file": "main.tf", "line": 1},
}

tf(resources) := {"kind": "terraform", "source": "hcl", "resources": resources}

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
