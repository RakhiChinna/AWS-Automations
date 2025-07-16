import boto3
import json
import logging
import datetime
import base64

iam_client = boto3.client('iam')
secrets_client = boto3.client('secretsmanager')
kms_client = boto3.client('kms')

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    kms_key_id = "arn:aws:kms:us-east-1:249864557561:key/0885b3e2-a4ed-40ff-8062-a3192129604c" 
    kms_key_id = "arn:aws:kms:us-east-1:249864557561:key/ada685b7-8f76-41bd-bfe7-9de2946b4129" # Replace with your KMS Key alias or ARN
    users = list_all_iam_users()

    if users:
        for user in users:
            user_name = user['UserName']
            try:
                tags = iam_client.list_user_tags(UserName=user_name)['Tags']
                tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            except Exception as e:
                logger.error(f"Failed to fetch tags for user {user_name}: {e}")
                continue  # Skip to the next user
            if 'SecretName' in tag_dict and 'AccessKeyName' in tag_dict and 'SecretKeyName' in tag_dict:
                secret_name = tag_dict['SecretName']
                access_key_name = tag_dict['AccessKeyName']
                secret_key_name = tag_dict['SecretKeyName']
                
                try:
                    secret = secrets_client.get_secret_value(SecretId=secret_name)
                    secret_data = json.loads(secret['SecretString'])
                    current_access_key_id = secret_data.get(access_key_name)
                    encrypted_value = base64.b64decode(current_access_key_id)
                    decrypt_accesskey_id = kms_client.decrypt(
                    CiphertextBlob=encrypted_value, KeyId=kms_key_id,)
                    if not current_access_key_id:
                        logger.warning(f"No existing access key found in secret for {user_name}. Skipping.")
                        continue
                    current_keys = iam_client.list_access_keys(UserName=user_name)['AccessKeyMetadata']
                    if not current_keys:
                        logger.warning(f"No access keys found for user {user_name}. Skipping.")
                        continue
                    
                    current_key_metadata = current_keys[0]  # Assuming the user has only one access key
                    create_date = current_key_metadata['CreateDate']

                    if is_key_older_than_one_minute(create_date):
                        iam_client.delete_access_key(UserName=user_name, AccessKeyId=decrypt_accesskey_id['Plaintext'].decode('utf-8'))
                        logger.info(f"Deleted old access key for user {user_name}")
                        new_key = iam_client.create_access_key(UserName=user_name)
                        new_access_key_id = new_key['AccessKey']['AccessKeyId']
                        new_secret_access_key = new_key['AccessKey']['SecretAccessKey']
                        encrypted_access_key = base64.b64encode(
                            kms_client.encrypt(KeyId=kms_key_id, Plaintext=new_access_key_id)['CiphertextBlob']
                        ).decode('utf-8')

                        encrypted_secret_key = base64.b64encode(
                            kms_client.encrypt(KeyId=kms_key_id, Plaintext=new_secret_access_key)['CiphertextBlob']
                        ).decode('utf-8')
                        secret_data[access_key_name] = encrypted_access_key
                        secret_data[secret_key_name] = encrypted_secret_key
                        secrets_client.put_secret_value(
                            SecretId=secret_name,
                            SecretString=json.dumps(secret_data)
                        )
                        
                        logger.info(f"Successfully rotated keys for user {user_name} and updated secret {secret_name}")
                    else:
                        logger.info(f"Access key for user {user_name} is less than 1 minute old. Skipping rotation.")
                except Exception as e:
                    logger.error(f"Error processing user {user_name}: {e}")
            else:
                logger.warning(f"Skipping user {user_name}: Missing required tags")
    else:
        logger.error("No IAM users found.")

    return {"message": "Key rotation complete"}

def is_key_older_than_one_minute(create_date):

    current_time = datetime.datetime.utcnow()
    age = current_time - create_date.replace(tzinfo=None)  # Remove timezone info if any
    return age > datetime.timedelta(minutes=1)

def list_all_iam_users():
    all_users = []
    try:
        response = iam_client.list_users(MaxItems=100)
        all_users.extend(response['Users'])
        while 'Marker' in response:
            response = iam_client.list_users(Marker=response['Marker'], MaxItems=100)
            all_users.extend(response['Users'])
        
        logger.info(f"Fetched {len(all_users)} IAM users.")
        return all_users
    
    except Exception as e:
        logger.error(f"Error fetching IAM users: {e}")
        return []

def update_or_create_secret(secret_name, key_value_pairs):
    try:
        secrets_client.describe_secret(SecretId=secret_name)
        current_secret = secrets_client.get_secret_value(SecretId=secret_name)
        current_secret_data = json.loads(current_secret['SecretString'])
        current_secret_data.update(key_value_pairs)
        
        secrets_client.put_secret_value(
            SecretId=secret_name,
            SecretString=json.dumps(current_secret_data)
        )
    except secrets_client.exceptions.ResourceNotFoundException:
        secrets_client.create_secret(
            Name=secret_name,
            SecretString=json.dumps(key_value_pairs)
        )
    except Exception as e:
        logger.error(f"Error updating or creating secret {secret_name}: {e}")