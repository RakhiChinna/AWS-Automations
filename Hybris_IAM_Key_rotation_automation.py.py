import boto3
import json
import logging
import datetime
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import os
iam_client = boto3.client('iam')
secrets_client = boto3.client('secretsmanager')
logger = logging.getLogger()
logger.setLevel(logging.INFO)
# Get AES Key and IV from environment variables
AES_KEY = base64.b64decode(os.environ['AES_KEY'])
AES_IV = base64.b64decode(os.environ['AES_IV'])
def lambda_handler(event, context):
    hybris_users = list_hybris_users()
    if hybris_users:
        for user in hybris_users:
            user_name = user['UserName']
            try:
                tags = iam_client.list_user_tags(UserName=user_name)['Tags']
                tag_dict = {tag['Key']: tag['Value'] for tag in tags}
            except Exception as e:
                logger.error(f"Failed to fetch tags for user {user_name}: {e}")
                continue
            if 'SecretName' in tag_dict and 'AccessKeyName' in tag_dict and 'SecretKeyName' in tag_dict:
                secret_name = tag_dict['SecretName']
                access_key_name = tag_dict['AccessKeyName']
                secret_key_name = tag_dict['SecretKeyName']
                try:
                    secret = secrets_client.get_secret_value(SecretId=secret_name)
                    secret_data = json.loads(secret['SecretString'])
                    encrypted_access_key = secret_data.get(access_key_name)
                    if not encrypted_access_key:
                        logger.warning(f"No access key found in secret for {user_name}. Skipping.")
                        continue
                    decrypted_access_key = aes_decrypt(encrypted_access_key)
                    current_keys = iam_client.list_access_keys(UserName=user_name)['AccessKeyMetadata']
                    if not current_keys:
                        logger.warning(f"No access keys found for user {user_name}. Skipping.")
                        continue
                    current_key_metadata = current_keys[0]
                    create_date = current_key_metadata['CreateDate']
                    if is_key_older_than_one_minute(create_date):
                        iam_client.delete_access_key(UserName=user_name, AccessKeyId=decrypted_access_key)
                        logger.info(f"Deleted old access key for user {user_name}")
                        new_key = iam_client.create_access_key(UserName=user_name)
                        new_access_key_id = new_key['AccessKey']['AccessKeyId']
                        new_secret_access_key = new_key['AccessKey']['SecretAccessKey']
                        encrypted_access_key = aes_encrypt(new_access_key_id)
                        encrypted_secret_key = aes_encrypt(new_secret_access_key)
                        secret_data[access_key_name] = encrypted_access_key
                        secret_data[secret_key_name] = encrypted_secret_key
                        secrets_client.put_secret_value(
                            SecretId=secret_name,
                            SecretString=json.dumps(secret_data)
                        )
                        logger.info(f"Successfully rotated keys for user {user_name} and updated secret {secret_name}")
                    else:
                        logger.info(f"Access key for user {user_name} is too new. Skipping rotation.")
                except Exception as e:
                    logger.error(f"Error processing user {user_name}: {e}")
            else:
                logger.warning(f"User {user_name} missing required tags. Skipping.")
    else:
        logger.info("No users with application=hybris tag found.")
    return {"message": "Key rotation complete"}
def is_key_older_than_one_minute(create_date):
    current_time = datetime.datetime.utcnow()
    age = current_time - create_date.replace(tzinfo=None)
    return age > datetime.timedelta(minutes=1)
def aes_decrypt(encrypted_b64):
    encrypted_data = base64.b64decode(encrypted_b64)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted.decode('utf-8')
def aes_encrypt(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted).decode('utf-8')
def list_hybris_users():
    hybris_users = []
    try:
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                try:
                    tags = iam_client.list_user_tags(UserName=user['UserName'])['Tags']
                    for tag in tags:
                        if tag['Key'] == 'application' and tag['Value'].lower() == 'hybris':
                            hybris_users.append(user)
                            break
                except Exception as e:
                    logger.warning(f"Could not retrieve tags for user {user['UserName']}: {e}")
    except Exception as e:
        logger.error(f"Error listing IAM users: {e}")
    return hybris_users






