# Security notes

This document records the security controls applied to the templates and scripts
in this repository, and the checks that are intentionally not implemented.

## Controls applied

### Cross-account role assumption is scoped to your organization

The IAM role created in each member account is assumed by a single Lambda
execution role in the central account. Two controls narrow that trust:

- The trust policy `Principal` names one specific role ARN. The central account
  ID is supplied as the `--mainaccount` argument to `CreateRoleforOrg.py`; it is
  not hardcoded.
- The trust policy carries a `Condition` on `aws:PrincipalOrgID`, supplied as
  `--orgid`. Without this condition, any principal whose ARN happened to match
  the expected pattern could obtain credentials in every account where the role
  exists.

The matching identity-based policy in the central account allows `sts:AssumeRole`
on `arn:aws:iam::*:role/<IAMRoleName>`. The account portion has to be a wildcard
because the role name is the same in every member account, so that statement
carries a `Condition` on `aws:ResourceOrgID` to keep the wildcard inside your own
organization.

### S3 buckets are private and logged

Both buckets created by `Cloudformation-createcredrepo.yaml` set:

- All four `PublicAccessBlockConfiguration` settings to `true`.
- `ObjectOwnership: BucketOwnerEnforced`, which disables ACLs.
- Default encryption with Amazon S3 managed keys (SSE-S3).
- Versioning.
- A bucket policy that denies any request made without TLS
  (`aws:SecureTransport: false`).

The credential report bucket delivers S3 server access logs to a dedicated
`<bucket>-access-logs` bucket. The log delivery grant is a bucket policy, not an
ACL, because ACLs are disabled. That grant is scoped to the `logging.s3.amazonaws.com`
service principal and conditioned on both `aws:SourceAccount` and `aws:SourceArn`,
so only log delivery for this one source bucket in this one account is permitted.

### No bucket name default

`S3BucketName` has no default value. S3 bucket names are globally unique, so a
template shipping a generic default such as `bucketname` encourages collisions
and name squatting. The parameter is validated against the S3 naming rules and
capped at 50 characters so that the derived `-access-logs` name stays within the
63-character limit.

### Least privilege on the Lambda policy

The Lambda policy grants only what the function calls: `s3:PutObject`,
`organizations:ListAccounts`, `sts:AssumeRole`, and the three CloudWatch Logs
actions. The earlier version also granted `logs:PutMetricFilter`,
`logs:StartQuery`, `logs:GetLogEvents`, and `s3:PutObjectAcl`, none of which the
function uses. The log group ARN in that policy now matches the function's actual
log group; previously it referred to a function name that the template does not
create.

`organizations:ListAccounts` does not support resource-level permissions, so `*`
is the only valid resource for that action.

## Checks intentionally not implemented

### Access logging on the access log bucket

Amazon S3 documents that a server access log destination bucket must not have
logging enabled pointing at itself, because that produces an infinite loop of log
records. Static analysis tools flag the log bucket for missing access logging;
this is a false positive for a destination bucket and is annotated in the
template with a Checkov `skip` and the reason.

Access to the log bucket is controlled instead by Block Public Access, bucket
owner enforced ownership, the TLS-only bucket policy, the scoped log delivery
grant, and a lifecycle rule that expires logs after 365 days.

### Lambda function in a VPC

The function calls only AWS APIs: AWS Organizations, AWS STS, IAM in each member
account, and Amazon S3. It receives no inbound network traffic and holds no
private network dependency. Placing it in a VPC would require either NAT
gateways or interface VPC endpoints for each of those services, roughly doubling
the size of this template and adding recurring cost, without reducing the
function's attack surface.

If your own control framework requires every Lambda function to run in a VPC,
add a `VpcConfig` block with private subnets and create interface endpoints for
`sts`, `organizations` (available in commercial Regions via a global endpoint),
and a gateway endpoint for S3.

### S3 Object Lock

Object Lock is not enabled. The credential report bucket is written to daily and
operators need to be able to expire old reports. Object Lock also disqualifies a
bucket from being a server access log destination and requires a bucket to be
created with the feature on, which prevents it from being applied to existing
deployments of this solution.

Versioning is enabled on both buckets, which covers accidental overwrite and
deletion.

### Lambda dead letter queue and reserved concurrency

Not implemented in this revision. The function is invoked once a day by a single
EventBridge rule, so concurrency contention is unlikely, and a failure is visible
in the function's return value and CloudWatch logs. Both are reasonable additions
if you run this in an environment where a missed daily run must raise an alert:
add `DeadLetterConfig.TargetArn` pointing at an SQS queue or SNS topic, and set
`ReservedConcurrentExecutions: 1`.

### Lambda environment variable encryption with a customer managed key

The two environment variables are an S3 bucket name and an IAM role name, neither
of which is sensitive. Lambda encrypts environment variables at rest with an AWS
managed key by default.

### Glue security configuration

The crawler reads objects that are already encrypted with SSE-S3 and writes
metadata to the AWS Glue Data Catalog. Add a security configuration if you need
CloudWatch log encryption for the crawler with a customer managed key.

## Handling the report data

The credential reports this solution collects list every IAM user in every
account, along with MFA status, password age, and access key rotation dates. That
is useful for auditing and equally useful to an attacker. Treat the central
bucket as sensitive:

- Restrict read access to the bucket to your security and audit roles only.
- Be careful with QuickSight dashboards built on this data. Sharing a dashboard,
  or a screenshot of one, can disclose account IDs and IAM user names.
- Consider a lifecycle rule that expires reports once they are past your audit
  retention requirement.
