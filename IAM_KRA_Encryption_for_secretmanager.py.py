import boto3
import json
import base64


def list_all_secrets(secrets_manager):
    all_secret_names = []
    next_token = None

    while True:
        response = secrets_manager.list_secrets(NextToken=next_token) if next_token else secrets_manager.list_secrets()
        secrets = response['SecretList']
        secret_names = [secret['Name'] for secret in secrets]
        all_secret_names.extend(secret_names)
        next_token = response.get('NextToken')
        if not next_token:
            break
    return all_secret_names


def update_secret_encryption(secret_name, kms_key_id):
    secrets_manager = boto3.client('secretsmanager', region_name='us-east-1')

    response = secrets_manager.get_secret_value(SecretId=secret_name)
    secret_dict = json.loads(response['SecretString'])

    for key, value in secret_dict.items():
        encrypted_value = boto3.client('kms').encrypt(KeyId=kms_key_id, Plaintext=value)['CiphertextBlob']
        secret_dict[key] = base64.b64encode(encrypted_value).decode('utf-8')

    secrets_manager.update_secret(SecretId=secret_name, SecretString=json.dumps(secret_dict))


def lambda_handler(event, context):
    secrets_manager = boto3.client('secretsmanager', region_name='us-east-1')
    all_secrets = list_all_secrets(secrets_manager)

    print("List of secrets:")
    print(all_secrets)

    if 'dev-cms-sqs-publish-epub-profiling-secret' in all_secrets:
        print("Secret 'dev-cms-sqs-publish-epub-profiling-secret' is present")

        update_secret_encryption('dev-cms-sqs-publish-epub-profiling-secret', 'ada685b7-8f76-41bd-bfe7-9de2946b4129')
    else:
        print("Secret 'dev-cms-sqs-publish-epub-profiling-secret' is not present")

    return {
        'statusCode': 200
    }