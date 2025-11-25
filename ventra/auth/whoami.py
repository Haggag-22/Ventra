import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from ventra.auth.store import load_ventra_creds, get_active_profile


def aws_whoami(profile=None):
    """
    Returns AWS identity using Ventra internal credentials.
    Profile selection:
      1. CLI-provided profile
      2. active Ventra profile
    """

    try:
        creds = load_ventra_creds(profile)
    except Exception as e:
        return {"error": str(e)}

    access_key = creds.get("access_key")
    secret_key = creds.get("secret_key")
    region = creds.get("region", "us-east-1")
    
    # Get the actual profile name used
    if profile:
        actual_profile = profile
    else:
        try:
            actual_profile, _ = get_active_profile()
        except:
            actual_profile = "active"

    try:
        session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        return {
            "Profile": actual_profile,
            "Account": identity.get("Account"),
            "Arn": identity.get("Arn"),
            "UserId": identity.get("UserId"),
            "Region": region
        }

    except NoCredentialsError:
        return {"error": "No valid AWS credentials found."}

    except ClientError as e:
        return {"error": str(e)}