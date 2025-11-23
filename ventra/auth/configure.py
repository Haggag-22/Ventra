import os
import configparser
import boto3
from botocore.exceptions import ClientError

AWS_CREDENTIALS = os.path.expanduser("~/.aws/credentials")
AWS_CONFIG = os.path.expanduser("~/.aws/config")


def configure_profile(profile, access_key, secret_key, region):
    """
    Save permanent AWS credentials exactly like AWS CLI.
    """

    # =============================
    # Validate credentials via STS
    # =============================
    try:
        sts = boto3.client(
            "sts",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )
        identity = sts.get_caller_identity()
        print(f"[✓] Valid credentials → {identity['Arn']}")
    except ClientError as e:
        print("❌ Invalid AWS credentials:", e)
        return

    # =============================
    # Write ~/.aws/credentials
    # =============================
    os.makedirs(os.path.dirname(AWS_CREDENTIALS), exist_ok=True)

    creds = configparser.RawConfigParser()
    if os.path.exists(AWS_CREDENTIALS):
        creds.read(AWS_CREDENTIALS)

    if not creds.has_section(profile):
        creds.add_section(profile)

    creds[profile]["aws_access_key_id"] = access_key
    creds[profile]["aws_secret_access_key"] = secret_key

    with open(AWS_CREDENTIALS, "w") as f:
        creds.write(f)

    # =============================
    # Write ~/.aws/config
    # =============================
    config = configparser.RawConfigParser()
    if os.path.exists(AWS_CONFIG):
        config.read(AWS_CONFIG)

    config_section = f"profile {profile}"
    if not config.has_section(config_section):
        config.add_section(config_section)

    config[config_section]["region"] = region
    config[config_section]["output"] = "json"

    with open(AWS_CONFIG, "w") as f:
        config.write(f)

    print(f"[✓] Profile '{profile}' saved permanently in ~/.aws/")