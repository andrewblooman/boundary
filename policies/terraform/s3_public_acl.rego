# METADATA
# title: S3 buckets must not use public ACLs
# description: >
#   A public-read or public-read-write ACL exposes every object in the bucket
#   to the internet. Public buckets are the most common cause of large-scale
#   cloud data leaks.
# custom:
#   id: BND-TF-002
#   severity: CRITICAL
#   target: terraform
#   compliance:
#     soc2: [CC6.1, CC6.6]
#     dora: [Art.9.3]
#     nis2: [Art.21.2i]
#     hipaa: [164.312(a)(1)]
#   remediation: |
#     Remove the public ACL (use "private") and add an
#     aws_s3_bucket_public_access_block with all four flags set to true. Serve
#     genuinely public content through CloudFront with origin access control.
#   fix_hint: change_value
#   references:
#     - https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
package boundary.terraform.s3_public_acl

import data.boundary.lib

public_acls := {"public-read", "public-read-write"}

deny contains finding if {
	some res in input.resources
	res.type in {"aws_s3_bucket", "aws_s3_bucket_acl"}
	acl := res.values.acl
	acl in public_acls
	finding := lib.finding(rego.metadata.chain(), res, {"acl": acl})
}
