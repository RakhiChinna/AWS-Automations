import boto3
import json
import base64

def decrypt_encrypted_value(encrypted_value_b64):
    # Decode the base64 encrypted value
    encrypted_value = base64.b64decode(encrypted_value_b64)

    # Create a KMS client
    kms_client = boto3.client('kms', region_name='us-east-1')

    # Decrypt the encrypted value using KMS
    response = kms_client.decrypt(CiphertextBlob=encrypted_value)

    # The plaintext value is in 'Plaintext' and needs to be decoded (if it's a string)
    plaintext = response['Plaintext'].decode('utf-8')

    return plaintext

def fetch_and_decrypt_secret(secret_name):
    secrets_manager = boto3.client('secretsmanager', region_name='us-east-1')

    # Fetch the secret value from Secrets Manager
    response = secrets_manager.get_secret_value(SecretId=secret_name)

    # Assuming the secret is a JSON object, load it as a dictionary
    secret_dict = json.loads(response['SecretString'])

    # For each key in the secret, try to decrypt its value
    decrypted_secrets = {}
    for key, encrypted_value_b64 in secret_dict.items():
        decrypted_secrets[key] = decrypt_encrypted_value(encrypted_value_b64)

    return decrypted_secrets

def update_secret(secret_name, decrypted_secrets):
    secrets_manager = boto3.client('secretsmanager', region_name='us-east-1')

    # Update the secret value in Secrets Manager with the decrypted secrets
    response = secrets_manager.update_secret(
        SecretId=secret_name,
        SecretString=json.dumps(decrypted_secrets)
    )

    return response

def lambda_handler(event, context):
    # Fetch and decrypt the secret 'validator_testcase'
    secret_name = 'dev-cms-frost-sqs-secret'
    decrypted_secrets = fetch_and_decrypt_secret(secret_name)

    # Print the decrypted values (e.g., access key)
    print("Decrypted Secrets:")
    print(decrypted_secrets)

    # Update the secret in Secrets Manager with the original (decrypted) values
    update_response = update_secret(secret_name, decrypted_secrets)

    print("Updated Secret Response:")
    print(update_response)

    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Secret updated successfully',
            'updatedSecretResponse': update_response
        })
    }