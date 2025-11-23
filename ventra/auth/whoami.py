# ventra/auth/whoami.py

import boto3
from botocore.exceptions import ClientError
from .store import get_active_profile


def aws_whoami():
    """
    Use Ventra's internal credentials to resolve the current AWS identity.
    """
    try:
        profile_name, creds = get_active_profile()
    except RuntimeError as e:
        return {"error": str(e), "Profile": None}

    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=creds["region"],
    )

    sts = session.client("sts")

    try:
        identity = sts.get_caller_identity()
    except ClientError as e:
        return {"error": str(e), "Profile": profile_name}

    return {
        "Profile": profile_name,
        "Account": identity.get("Account"),
        "Arn": identity.get("Arn"),
        "UserId": identity.get("UserId"),
    }