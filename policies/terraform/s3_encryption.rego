# METADATA
# title: S3 buckets must enforce encryption at rest
# description: >
#   An S3 bucket without server-side encryption stores objects in plaintext.
#   If access controls fail or credentials leak, the data itself has no last
#   line of defence.
# custom:
#   id: BND-TF-001
#   severity: HIGH
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.7]
#     dora: [Art.9.2]
#     nis2: [Art.21.2h]
#     hipaa: [164.312(a)(2)(iv)]
#   remediation: |
#     Add an aws_s3_bucket_server_side_encryption_configuration resource for the
#     bucket (AES256 or aws:kms), or an inline server_side_encryption_configuration
#     block on older AWS providers.
#   fix_hint: add_block
#   references:
#     - https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingServerSideEncryption.html
package boundary.terraform.s3_encryption

import data.boundary.lib

deny contains finding if {
	some bucket in input.resources
	bucket.type == "aws_s3_bucket"
	not bucket.values.server_side_encryption_configuration
	not has_sse_resource(bucket)
	finding := lib.finding(rego.metadata.chain(), bucket, {"encryption": "not configured"})
}

has_sse_resource(bucket) if {
	some sse in input.resources
	sse.type == "aws_s3_bucket_server_side_encryption_configuration"
	lib.references(sse.values, bucket.address)
}

# Plan JSON resolves references, so the bucket linkage may be an unknown value
# that never appears in `after`; treat any SSE-config resource as coverage there.
has_sse_resource(_) if {
	input.source == "plan"
	some sse in input.resources
	sse.type == "aws_s3_bucket_server_side_encryption_configuration"
}
