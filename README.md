## Solution Overview

This repository holds the code of the artifact [Visualize IAM credential reports for all AWS accounts using Amazon QuickSight](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/visualize-iam-credential-reports-for-all-aws-accounts-using-amazon-quicksight.html?did=pg_card&trk=pg_card). It provides you prescriptive guidance to create IAM credential reports from all AWS accounts and stores them at a central location. This solution uses Amazon QuickSight to create dashboards enabling you to audit the IAM credentials at scale.

This artiact is published in AWS documents. You can read the entire content @ [Visualize IAM credential reports for all AWS accounts using Amazon QuickSight](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/visualize-iam-credential-reports-for-all-aws-accounts-using-amazon-quicksight.html)

## Deployment

### 1. Create the central resources

Deploy `Cloudformation-createcredrepo.yaml` in the account that will hold the
credential reports. The template takes three parameters:

| Parameter | Required | Description |
|---|---|---|
| `S3BucketName` | Yes | Name of the bucket to create for the reports. S3 bucket names are globally unique, so supply a name you own. There is deliberately no default. A second bucket named `<S3BucketName>-access-logs` is created for server access logs. |
| `OrganizationId` | Yes | Your AWS Organizations ID, for example `o-abc1234567`. Restricts cross-account role assumption to accounts inside your own organization. |
| `IAMRoleName` | No | Name of the role the Lambda function assumes in each member account. Defaults to `iamcredentialrole`. |

Note the `LambdaRole` and `OrganizationId` stack outputs; the next step needs both.

### 2. Create the member account roles

`CreateRoleforOrg.py` creates the report-generating role in every account in the
organization. Run it with credentials in the organization's management account.

```bash
python3 CreateRoleforOrg.py \
  --lambdarole  <name of the LambdaRole from step 1> \
  --mainaccount <12-digit account ID where you deployed the stack> \
  --orgid       <your AWS Organizations ID, e.g. o-abc1234567> \
  --masterrole  <role this script assumes in each account to create IAM roles> \
  --credrole    <optional name for the created role>
```

`--mainaccount` and `--orgid` are required. The central account ID is a
parameter rather than a hardcoded value, and `--orgid` is used to add an
`aws:PrincipalOrgID` condition to the trust policy of every role the script
creates, so that only principals inside your organization can assume it.

## Security

The security controls applied to these templates, and the static analysis checks
that are intentionally not implemented, are documented in
[SECURITY-NOTES.md](SECURITY-NOTES.md).

The credential reports this solution collects describe the IAM posture of every
account in your organization. Treat the central bucket, and any dashboard or
screenshot derived from it, as sensitive.

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
