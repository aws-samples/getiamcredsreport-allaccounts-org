import boto3, json, sys, argparse
from botocore.exceptions import ClientError

def assume_role(target_account, master_role):
    '''
      Description: Get cross account credentials for given AWS target account
      Arguments:
          master_role_arn: Master account role ARN
          target_account: Target account number
      Returns: assubmed cross account role credentials
    '''
    sts = boto3.client('sts')
    try:
        assume_role_object = sts.assume_role(
            RoleArn="arn:aws:iam::{}:role/{}".format(target_account,master_role),
            RoleSessionName="AssumingCrossAccountRole"
        )
    except Exception as err:
        print("Error ocurred while assuming role: {}".format(err))
        return False
    role = dict()
    role['AccessKeyId'] = assume_role_object['Credentials']['AccessKeyId']
    role['SecretAccessKey'] = assume_role_object['Credentials']['SecretAccessKey']
    role['SessionToken'] = assume_role_object['Credentials']['SessionToken']
    return role

def createrole(AccessKeyId,SecretAccessKey,SessionToken, account, lambda_role, iam_role):
    iam_client = boto3.client('iam', 
        aws_access_key_id=AccessKeyId,
        aws_secret_access_key=SecretAccessKey, 
        aws_session_token=SessionToken
    )
    
    # Variables
    role_name=iam_role
    policy_name = role_name + '_policy'
    policy_arn = ''
    
    # Role Policy
    policy_json = {
        "Version": "2012-10-17",
        "Statement": [
            {
            "Effect": "Allow",
            "Action": [
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport"
            ],
            "Resource": "*"
            }
        ]
    }
    
    # Create Policy
    try:
        policy_res = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_json)
        )
        policy_arn = policy_res['Policy']['Arn']
    except ClientError as error:
        if error.response['Error']['Code'] == 'EntityAlreadyExists':
            print('Policy already exists... hence using the same policy')
            policy_arn = 'arn:aws:iam::' + account + ':policy/' + policy_name
        else:
            print('Unexpected error occurred when creating policy... hence cleaning up', error)
            try:
                iam_client.delete_role(
                    RoleName= role_name
            )
            except ClientError as e:
                print ("Role was not found so can't delete", e)
            return('Role could not be created...', error)
    
    # Trust Policy
    trust_relationship_policy_another_aws_role = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::299344511603:role/"+lambda_role
                    ]
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    
    # Creating Role 
    try:
        role_response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_relationship_policy_another_aws_role),
            Description='This role to create credential reports'
        )
    except ClientError as error:
        if error.response['Error']['Code'] == 'EntityAlreadyExists':
            print('Role already exists... hence exiting from here')
        else:
            print('Unexpected error occurred... Role could not be created', error)
    
    # Attach policy to Role
    try:
        policy_attach_res = iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy_arn
        )
    except ClientError as error:
        print ('Unexpected error occurred while attaching policy to role... hence cleaning up')
        try: 
            iam_client.delete_role(
                RoleName= role_name
            )
        except ClientError as e:
            print (e)
            
        return ('Role could not be created...', error)
        
    return ('Role {0} successfully got created'.format(role_name))
    
  
# Main Function - use to call other functions
def main():
    # Arguments
    parser = argparse.ArgumentParser(description="Help you create Role that will help you create credential reports in accounts across org")
    parser.add_argument(
        '-lr',
        '--lambdarole',
        dest='lambdarole',
        help="Please provide name of the role from main account that is allowed to assume role in other accounts",
        required=True
        )
    parser.add_argument(
        '-mr',
        '--masterrole',
        dest='masterrole',
        help="Please provide name of the role which has permissiong to create IAM roles in all accounts",
        required=True
        )
    parser.add_argument(
        '-cr',
        '--credrole',
        dest='credrole',
        help="Please provide name of the role that would create credential reports. It's optional. By Default it creates role --> iam-credential-report-lambda-role1",
        required=False,
        default='iam-credential-report-lambda-role1'
        )

    try:
        args = parser.parse_args()
        lambda_role = args.lambdarole
        master_role = args.masterrole
        iam_role = args.credrole
        
    
        try:
            client = boto3.client('organizations')
            accountlist=[]
            response = client.list_accounts()
            for i in response['Accounts']:
                accountlist.append(i['Id'])

            while 'NextToken' in response:
                response = client.list_accounts(NextToken=response['NextToken'])
                for i in response['Accounts']:
                    accountlist.append(i['Id'])
            print (accountlist)
            for account in accountlist:
                print ("Account Number --> ", account)
                creds=assume_role(account, master_role)
                if creds != False:
                    createrole(creds['AccessKeyId'],creds['SecretAccessKey'],creds['SessionToken'], account, lambda_role, iam_role)
        except ClientError as e:
            print(e)
    
    except AttributeError as e:
        exit
        
if __name__ == "__main__":
    main()
