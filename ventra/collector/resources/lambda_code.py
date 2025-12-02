"""
Lambda Code Collector
Downloads Lambda function code (ZIP) - forensics gold.
This is the actual malicious code attackers deploy.
"""
import os
import json
import boto3
import zipfile
import io
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_lambda_client(region):
    """Lambda client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("lambda")


def _save_json_file(output_dir, filename, data):
    """Save data to JSON file with pretty printing."""
    filepath = os.path.join(output_dir, filename)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return filepath
    except Exception as e:
        print(f"    ❌ Error saving {filename}: {e}")
        return None


def _extract_zip_info(zip_data):
    """Extract file list and basic info from ZIP."""
    try:
        zip_file = zipfile.ZipFile(io.BytesIO(zip_data))
        files = []
        for info in zip_file.infolist():
            files.append({
                "filename": info.filename,
                "file_size": info.file_size,
                "compress_size": info.compress_size,
                "date_time": str(info.date_time),
                "is_dir": info.is_dir(),
            })
        return files
    except Exception as e:
        return None


def run_lambda_code(args):
    """Collect and download Lambda function code."""
    function_name = args.name
    print(f"[+] Lambda Code Collector")
    print(f"    Function:    {function_name}")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    output_dir = os.path.join(output_dir, "resources")
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        lambda_client = _get_lambda_client(args.region)
    except Exception as e:
        print(f"❌ Error getting Lambda client: {e}")
        return
    
    try:
        code_data = {}
        
        print("[+] Downloading function code...")
        try:
            response = lambda_client.get_function(FunctionName=function_name)
            code_location = response.get("Code", {}).get("Location")
            code_repository_type = response.get("Code", {}).get("RepositoryType")
            
            code_data = {
                "FunctionName": function_name,
                "FunctionArn": response.get("Configuration", {}).get("FunctionArn"),
                "CodeLocation": code_location,
                "RepositoryType": code_repository_type,
                "CodeSize": response.get("Configuration", {}).get("CodeSize"),
                "CodeSha256": response.get("Configuration", {}).get("CodeSha256"),
            }
            
            # Download the code if it's a ZIP (not container image)
            if code_repository_type == "S3":
                print(f"    ✓ Code location: {code_location}")
                print(f"    ⚠ Code is stored in S3, download manually or use S3 collector")
                code_data["Downloaded"] = False
                code_data["Message"] = "Code stored in S3, use S3 collector to download"
            else:
                # Try to download via get_function URL
                import urllib.request
                try:
                    with urllib.request.urlopen(code_location) as response_url:
                        zip_data = response_url.read()
                        
                        # Save ZIP file
                        safe_name = function_name.replace(":", "_").replace("/", "_")
                        zip_filename = f"lambda_code_{safe_name}.zip"
                        zip_filepath = os.path.join(output_dir, zip_filename)
                        with open(zip_filepath, "wb") as f:
                            f.write(zip_data)
                        
                        code_data["Downloaded"] = True
                        code_data["ZipFile"] = zip_filename
                        code_data["ZipSize"] = len(zip_data)
                        
                        # Extract ZIP contents info
                        zip_info = _extract_zip_info(zip_data)
                        code_data["ZipContents"] = zip_info
                        
                        print(f"    ✓ Downloaded code ZIP ({len(zip_data)} bytes)")
                        if zip_info:
                            print(f"    ✓ ZIP contains {len(zip_info)} file(s)")
                except Exception as e:
                    print(f"    ⚠ Error downloading code: {e}")
                    code_data["Downloaded"] = False
                    code_data["Error"] = str(e)
            
        except ClientError as e:
            print(f"    ❌ Error getting function code: {e}")
            return
        
        # Save metadata file
        safe_name = function_name.replace(":", "_").replace("/", "_")
        filename = f"lambda_code_{safe_name}.json"
        filepath = _save_json_file(output_dir, filename, code_data)
        if filepath:
            print(f"\n[✓] Saved code metadata → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

