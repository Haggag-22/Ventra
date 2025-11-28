"""
DynamoDB All Collector
Collects all DynamoDB information for a table (table info, attributes, items, backups, streams, and exports) into a single combined file.
"""
import os
import json
import base64
import boto3
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_dynamodb_client(region):
    """DynamoDB client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("dynamodb")


def _get_dynamodbstreams_client(region):
    """DynamoDB Streams client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("dynamodbstreams")


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


def _resolve_table_name(dynamodb_client, table_identifier):
    """
    Resolve table identifier (name or ARN) to table name.
    Returns table name if found, None otherwise.
    """
    # If it's already a valid table name, return it
    try:
        response = dynamodb_client.describe_table(TableName=table_identifier)
        return table_identifier
    except ClientError:
        pass
    
    # Try to extract table name from ARN
    if table_identifier.startswith("arn:aws:dynamodb:"):
        # Extract table name from ARN format: arn:aws:dynamodb:region:account:table/table-name
        parts = table_identifier.split("/")
        if len(parts) > 1:
            table_name = parts[-1]
            try:
                response = dynamodb_client.describe_table(TableName=table_name)
                return table_name
            except ClientError:
                pass
    
    # Try listing all tables and finding a match
    try:
        paginator = dynamodb_client.get_paginator("list_tables")
        for page in paginator.paginate():
            for table_name in page.get("TableNames", []):
                if table_name == table_identifier or table_name.startswith(table_identifier):
                    return table_name
    except ClientError:
        pass
    
    return None


def _collect_table_info(dynamodb_client, table_name):
    """Collect table information."""
    try:
        table_response = dynamodb_client.describe_table(TableName=table_name)
        table_desc = table_response.get("Table", {})
        
        table_info = {
            "TableName": table_desc.get("TableName"),
            "TableArn": table_desc.get("TableArn"),
            "TableStatus": table_desc.get("TableStatus"),
            "CreationDateTime": str(table_desc.get("CreationDateTime", "")),
            "TableSizeBytes": table_desc.get("TableSizeBytes", 0),
            "ItemCount": table_desc.get("ItemCount", 0),
            "AttributeDefinitions": table_desc.get("AttributeDefinitions", []),
            "KeySchema": table_desc.get("KeySchema", []),
            "BillingModeSummary": table_desc.get("BillingModeSummary"),
            "ProvisionedThroughput": table_desc.get("ProvisionedThroughput"),
            "StreamSpecification": table_desc.get("StreamSpecification"),
            "LatestStreamArn": table_desc.get("LatestStreamArn"),
            "GlobalSecondaryIndexes": table_desc.get("GlobalSecondaryIndexes", []),
            "LocalSecondaryIndexes": table_desc.get("LocalSecondaryIndexes", []),
            "RestoreSummary": table_desc.get("RestoreSummary"),
            "SSEDescription": table_desc.get("SSEDescription"),
            "ArchivalSummary": table_desc.get("ArchivalSummary"),
            "TableClass": table_desc.get("TableClass"),
        }
        
        # Get table tags
        try:
            tags_response = dynamodb_client.list_tags_of_resource(ResourceArn=table_desc.get("TableArn"))
            table_info["Tags"] = {tag["Key"]: tag["Value"] for tag in tags_response.get("Tags", [])}
        except ClientError as e:
            print(f"      ⚠ Error getting tags: {e}")
            table_info["Tags"] = {}
        
        return table_info
    except ClientError as e:
        print(f"      ⚠ Error getting table info: {e}")
        return None


def _collect_backups(dynamodb_client, table_name):
    """Collect backups for a specific table."""
    backups = []
    
    try:
        paginator = dynamodb_client.get_paginator("list_backups")
        for page in paginator.paginate(TableName=table_name):
            for backup in page.get("BackupSummaries", []):
                backup_arn = backup.get("BackupArn")
                
                backup_info = {
                    "TableName": backup.get("TableName"),
                    "TableArn": backup.get("TableArn"),
                    "BackupArn": backup_arn,
                    "BackupName": backup.get("BackupName"),
                    "BackupStatus": backup.get("BackupStatus"),
                    "BackupType": backup.get("BackupType"),
                    "BackupCreationDateTime": str(backup.get("BackupCreationDateTime", "")),
                    "BackupExpiryDateTime": str(backup.get("BackupExpiryDateTime", "")) if backup.get("BackupExpiryDateTime") else None,
                    "BackupSizeBytes": backup.get("BackupSizeBytes", 0),
                }
                
                # Get detailed backup information
                try:
                    backup_details = dynamodb_client.describe_backup(BackupArn=backup_arn)
                    backup_desc = backup_details.get("BackupDescription", {})
                    backup_info["BackupDetails"] = {
                        "BackupArn": backup_desc.get("BackupArn"),
                        "BackupName": backup_desc.get("BackupName"),
                        "BackupStatus": backup_desc.get("BackupStatus"),
                        "BackupType": backup_desc.get("BackupType"),
                        "BackupCreationDateTime": str(backup_desc.get("BackupCreationDateTime", "")),
                        "BackupExpiryDateTime": str(backup_desc.get("BackupExpiryDateTime", "")) if backup_desc.get("BackupExpiryDateTime") else None,
                        "BackupSizeBytes": backup_desc.get("BackupSizeBytes", 0),
                        "SourceTableDetails": backup_desc.get("SourceTableDetails", {}),
                        "SourceTableFeatureDetails": backup_desc.get("SourceTableFeatureDetails", {}),
                    }
                except ClientError as e:
                    print(f"      ⚠ Error getting backup details: {e}")
                
                backups.append(backup_info)
    except ClientError as e:
        print(f"      ⚠ Error getting backups: {e}")
    
    return backups


def _collect_streams(dynamodb_client, streams_client, table_name, stream_arn):
    """Collect stream information for a table."""
    if not stream_arn:
        return None
    
    try:
        stream_info = {
            "StreamArn": stream_arn,
        }
        
        # Get stream details
        try:
            stream_response = streams_client.describe_stream(StreamArn=stream_arn)
            stream_desc = stream_response.get("StreamDescription", {})
            stream_table_name = stream_desc.get("TableName")
            if isinstance(stream_table_name, dict):
                stream_table_name = stream_table_name.get("TableName", table_name)
            elif not stream_table_name:
                stream_table_name = table_name
            
            stream_info["StreamDetails"] = {
                "StreamArn": stream_desc.get("StreamArn"),
                "StreamLabel": stream_desc.get("StreamLabel"),
                "StreamStatus": stream_desc.get("StreamStatus"),
                "StreamViewType": stream_desc.get("StreamViewType"),
                "CreationRequestDateTime": str(stream_desc.get("CreationRequestDateTime", "")),
                "TableName": stream_table_name,
                "KeySchema": stream_desc.get("KeySchema", []),
                "Shards": stream_desc.get("Shards", []),
            }
        except ClientError as e:
            print(f"      ⚠ Error getting stream details: {e}")
        
        return stream_info
    except ClientError as e:
        print(f"      ⚠ Error getting stream: {e}")
        return None


def _collect_table_items(dynamodb_client, table_name, limit=None):
    """Collect all items (keys and data) from the table by scanning."""
    items = []
    item_count = 0
    
    try:
        print(f"[+] Scanning table items...")
        
        # Use scan to get all items
        scan_params = {
            "TableName": table_name,
        }
        
        # Get paginator for scan
        paginator = dynamodb_client.get_paginator("scan")
        
        for page in paginator.paginate(**scan_params):
            page_items = page.get("Items", [])
            
            for item in page_items:
                if limit and item_count >= limit:
                    print(f"      ⚠ Reached limit of {limit} items")
                    break
                
                # Convert DynamoDB item format to regular dict
                converted_item = {}
                for key, value_dict in item.items():
                    # DynamoDB returns items as {"S": "value"}, {"N": "123"}, etc.
                    # Convert to readable format
                    if "S" in value_dict:
                        converted_item[key] = value_dict["S"]
                    elif "N" in value_dict:
                        # Try to convert to int, fallback to float
                        try:
                            num_str = value_dict["N"]
                            if "." in num_str:
                                converted_item[key] = float(num_str)
                            else:
                                converted_item[key] = int(num_str)
                        except (ValueError, TypeError):
                            converted_item[key] = value_dict["N"]
                    elif "B" in value_dict:
                        # Binary data - encode as base64
                        converted_item[key] = base64.b64encode(value_dict["B"]).decode("utf-8")
                    elif "SS" in value_dict:
                        converted_item[key] = value_dict["SS"]
                    elif "NS" in value_dict:
                        converted_item[key] = [int(n) if "." not in n else float(n) for n in value_dict["NS"]]
                    elif "BS" in value_dict:
                        converted_item[key] = [base64.b64encode(b).decode("utf-8") for b in value_dict["BS"]]
                    elif "M" in value_dict:
                        # Recursively convert map
                        converted_map = {}
                        for map_key, map_value in value_dict["M"].items():
                            if "S" in map_value:
                                converted_map[map_key] = map_value["S"]
                            elif "N" in map_value:
                                try:
                                    num_str = map_value["N"]
                                    converted_map[map_key] = int(num_str) if "." not in num_str else float(num_str)
                                except (ValueError, TypeError):
                                    converted_map[map_key] = map_value["N"]
                            elif "M" in map_value:
                                # Nested map - convert recursively
                                nested_map = {}
                                for nested_key, nested_value in map_value["M"].items():
                                    if "S" in nested_value:
                                        nested_map[nested_key] = nested_value["S"]
                                    elif "N" in nested_value:
                                        try:
                                            nested_map[nested_key] = int(nested_value["N"]) if "." not in nested_value["N"] else float(nested_value["N"])
                                        except (ValueError, TypeError):
                                            nested_map[nested_key] = nested_value["N"]
                                    else:
                                        nested_map[nested_key] = nested_value
                                converted_map[map_key] = nested_map
                            else:
                                converted_map[map_key] = map_value
                        converted_item[key] = converted_map
                    elif "L" in value_dict:
                        # List - convert each element
                        converted_list = []
                        for list_item in value_dict["L"]:
                            if "S" in list_item:
                                converted_list.append(list_item["S"])
                            elif "N" in list_item:
                                try:
                                    num_str = list_item["N"]
                                    converted_list.append(int(num_str) if "." not in num_str else float(num_str))
                                except (ValueError, TypeError):
                                    converted_list.append(list_item["N"])
                            else:
                                converted_list.append(list_item)
                        converted_item[key] = converted_list
                    elif "BOOL" in value_dict:
                        converted_item[key] = value_dict["BOOL"]
                    elif "NULL" in value_dict:
                        converted_item[key] = None
                    else:
                        # Unknown type - keep as is
                        converted_item[key] = value_dict
                
                items.append(converted_item)
                item_count += 1
                
                if item_count % 1000 == 0:
                    print(f"      ... Scanned {item_count} items so far...")
            
            if limit and item_count >= limit:
                break
        
        print(f"    ✓ Scanned {len(items)} item(s)")
        return items
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ResourceNotFoundException":
            print(f"    ⚠ Table not found or access denied")
        else:
            print(f"    ⚠ Error scanning table: {e}")
        return []
    except Exception as e:
        print(f"    ⚠ Error scanning table items: {e}")
        return []


def _collect_exports(dynamodb_client, table_arn):
    """Collect exports for a table."""
    exports = []
    
    try:
        # list_exports doesn't support pagination - use regular call
        response = dynamodb_client.list_exports(TableArn=table_arn, MaxResults=100)
        for export in response.get("ExportSummaries", []):
            export_arn = export.get("ExportArn")
            
            export_info = {
                "ExportArn": export_arn,
                "ExportStatus": export.get("ExportStatus"),
                "ExportType": export.get("ExportType"),
                "ExportTime": str(export.get("ExportTime", "")),
                "S3Bucket": export.get("S3Bucket"),
                "S3Prefix": export.get("S3Prefix"),
                "S3SseAlgorithm": export.get("S3SseAlgorithm"),
                "S3SseKmsKeyId": export.get("S3SseKmsKeyId"),
                "ExportFormat": export.get("ExportFormat"),
                "ItemCount": export.get("ItemCount", 0),
                "ExportSizeBytes": export.get("ExportSizeBytes", 0),
            }
            
            # Get detailed export information
            try:
                export_details = dynamodb_client.describe_export(ExportArn=export_arn)
                export_desc = export_details.get("ExportDescription", {})
                export_info["ExportDetails"] = {
                    "ExportArn": export_desc.get("ExportArn"),
                    "ExportStatus": export_desc.get("ExportStatus"),
                    "ExportType": export_desc.get("ExportType"),
                    "ExportTime": str(export_desc.get("ExportTime", "")),
                    "S3Bucket": export_desc.get("S3Bucket"),
                    "S3Prefix": export_desc.get("S3Prefix"),
                    "S3SseAlgorithm": export_desc.get("S3SseAlgorithm"),
                    "S3SseKmsKeyId": export_desc.get("S3SseKmsKeyId"),
                    "ExportFormat": export_desc.get("ExportFormat"),
                    "ItemCount": export_desc.get("ItemCount", 0),
                    "ExportSizeBytes": export_desc.get("ExportSizeBytes", 0),
                    "FailureCode": export_desc.get("FailureCode"),
                    "FailureMessage": export_desc.get("FailureMessage"),
                    "IncrementalExportSpecification": export_desc.get("IncrementalExportSpecification"),
                }
            except ClientError as e:
                print(f"      ⚠ Error getting export details: {e}")
            
            exports.append(export_info)
        
        # Handle pagination manually if needed
        next_token = response.get("NextToken")
        while next_token:
            try:
                response = dynamodb_client.list_exports(TableArn=table_arn, MaxResults=100, NextToken=next_token)
                for export in response.get("ExportSummaries", []):
                    export_arn = export.get("ExportArn")
                    
                    export_info = {
                        "ExportArn": export_arn,
                        "ExportStatus": export.get("ExportStatus"),
                        "ExportType": export.get("ExportType"),
                        "ExportTime": str(export.get("ExportTime", "")),
                        "S3Bucket": export.get("S3Bucket"),
                        "S3Prefix": export.get("S3Prefix"),
                        "S3SseAlgorithm": export.get("S3SseAlgorithm"),
                        "S3SseKmsKeyId": export.get("S3SseKmsKeyId"),
                        "ExportFormat": export.get("ExportFormat"),
                        "ItemCount": export.get("ItemCount", 0),
                        "ExportSizeBytes": export.get("ExportSizeBytes", 0),
                    }
                    
                    try:
                        export_details = dynamodb_client.describe_export(ExportArn=export_arn)
                        export_desc = export_details.get("ExportDescription", {})
                        export_info["ExportDetails"] = {
                            "ExportArn": export_desc.get("ExportArn"),
                            "ExportStatus": export_desc.get("ExportStatus"),
                            "ExportType": export_desc.get("ExportType"),
                            "ExportTime": str(export_desc.get("ExportTime", "")),
                            "S3Bucket": export_desc.get("S3Bucket"),
                            "S3Prefix": export_desc.get("S3Prefix"),
                            "S3SseAlgorithm": export_desc.get("S3SseAlgorithm"),
                            "S3SseKmsKeyId": export_desc.get("S3SseKmsKeyId"),
                            "ExportFormat": export_desc.get("ExportFormat"),
                            "ItemCount": export_desc.get("ItemCount", 0),
                            "ExportSizeBytes": export_desc.get("ExportSizeBytes", 0),
                            "FailureCode": export_desc.get("FailureCode"),
                            "FailureMessage": export_desc.get("FailureMessage"),
                            "IncrementalExportSpecification": export_desc.get("IncrementalExportSpecification"),
                        }
                    except ClientError as e:
                        print(f"      ⚠ Error getting export details: {e}")
                    
                    exports.append(export_info)
                
                next_token = response.get("NextToken")
            except ClientError as e:
                print(f"      ⚠ Error getting exports (pagination): {e}")
                break
                
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        # Exports might not be available or table might not have exports
        if error_code not in ["ResourceNotFoundException", "AccessDeniedException"]:
            print(f"      ⚠ Error getting exports: {e}")
    except Exception as e:
        print(f"      ⚠ Error getting exports: {e}")
    
    return exports


def run_dynamodb_all(args):
    """Collect all DynamoDB data for a specific table into a single file."""
    table_identifier = getattr(args, "table", None)
    
    if not table_identifier:
        print("❌ Error: --table parameter is required")
        print("   Usage: ventra collect dynamodb all --case <case> --table <table_name_or_arn>")
        return
    
    print(f"[+] DynamoDB All Collector")
    print(f"    Table:       {table_identifier}")
    print(f"    Region:      {args.region}\n")
    
    # Resolve output directory
    if hasattr(args, "case_dir") and args.case_dir:
        output_dir = args.case_dir
    elif hasattr(args, "output") and args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join(os.path.expanduser("~"), "Desktop", "Ventra", "output")
    
    os.makedirs(output_dir, exist_ok=True)
    print(f"    Output:      {output_dir}\n")
    
    try:
        dynamodb_client = _get_dynamodb_client(args.region)
        streams_client = _get_dynamodbstreams_client(args.region)
    except Exception as e:
        print(f"❌ Error getting DynamoDB client: {e}")
        return
    
    try:
        # Resolve table name
        print(f"[+] Resolving table identifier...")
        table_name = _resolve_table_name(dynamodb_client, table_identifier)
        if not table_name:
            print(f"❌ Error: Could not find table with identifier: {table_identifier}")
            return
        
        print(f"    ✓ Found table: {table_name}\n")
        
        # Collect all data
        all_data = {
            "TableName": table_name,
            "TableInfo": None,
            "TableItems": [],
            "Backups": [],
            "Stream": None,
            "Exports": [],
        }
        
        # Collect table info
        print(f"[+] Collecting table information...")
        try:
            all_data["TableInfo"] = _collect_table_info(dynamodb_client, table_name)
            if all_data["TableInfo"]:
                print(f"    ✓ Collected table info")
                table_arn = all_data["TableInfo"].get("TableArn")
                stream_arn = all_data["TableInfo"].get("LatestStreamArn")
            else:
                print(f"    ⚠ Failed to collect table info (continuing)")
                table_arn = None
                stream_arn = None
        except Exception as e:
            print(f"    ⚠ Error collecting table info: {e} (continuing)")
            all_data["TableInfo"] = None
            table_arn = None
            stream_arn = None
        
        # Collect table items (keys and data)
        limit = getattr(args, "limit", None)
        if limit:
            print(f"[+] Collecting table items (limit: {limit})...")
        else:
            print(f"[+] Collecting all table items...")
        try:
            all_data["TableItems"] = _collect_table_items(dynamodb_client, table_name, limit=limit)
            all_data["TotalItemsCollected"] = len(all_data["TableItems"])
            if all_data["TableItems"]:
                print(f"    ✓ Collected {len(all_data['TableItems'])} item(s)")
            else:
                print(f"    ⚠ No items found or table is empty")
        except Exception as e:
            print(f"    ⚠ Error collecting table items: {e} (continuing)")
            all_data["TableItems"] = []
            all_data["TotalItemsCollected"] = 0
        
        # Collect backups
        print(f"[+] Collecting backups...")
        try:
            all_data["Backups"] = _collect_backups(dynamodb_client, table_name)
            print(f"    ✓ Found {len(all_data['Backups'])} backup(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting backups: {e} (continuing)")
            all_data["Backups"] = []
        
        # Collect streams
        if stream_arn:
            print(f"[+] Collecting stream information...")
            try:
                all_data["Stream"] = _collect_streams(dynamodb_client, streams_client, table_name, stream_arn)
                if all_data["Stream"]:
                    print(f"    ✓ Collected stream info")
                else:
                    print(f"    ⚠ No stream details available")
            except Exception as e:
                print(f"    ⚠ Error collecting stream: {e} (continuing)")
                all_data["Stream"] = None
        else:
            print(f"[+] Stream: Not enabled for this table")
            all_data["Stream"] = None
        
        # Collect exports
        print(f"[+] Collecting exports...")
        try:
            all_data["Exports"] = _collect_exports(dynamodb_client, table_arn)
            print(f"    ✓ Found {len(all_data['Exports'])} export(s)")
        except Exception as e:
            print(f"    ⚠ Error collecting exports: {e}")
            all_data["Exports"] = []
        
        # Get table ID for filename - sanitize table name
        # Replace characters that might cause issues in filenames
        table_id = table_name.replace("-", "_").replace(".", "_").replace("/", "_")
        filename = f"dynamodb_{table_id}_all.json"
        
        # Save combined file
        filepath = _save_json_file(output_dir, filename, all_data)
        if filepath:
            print(f"\n[✓] Saved all DynamoDB data → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

