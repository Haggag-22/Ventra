"""
CloudWatch Metrics Collector
Collects CloudWatch metrics, optionally filtered by namespace and dimensions.
"""
import os
import json
import boto3
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError
from ventra.auth.store import get_active_profile


def _get_cloudwatch_client(region):
    """CloudWatch client using Ventra's internal credentials."""
    profile_name, creds = get_active_profile()
    session = boto3.Session(
        aws_access_key_id=creds["access_key"],
        aws_secret_access_key=creds["secret_key"],
        region_name=region,
    )
    return session.client("cloudwatch")


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


def run_cloudwatch_metrics(args):
    """Collect CloudWatch metrics."""
    namespace = getattr(args, "namespace", None)
    dimensions = getattr(args, "dimensions", None)
    hours = getattr(args, "hours", 24)  # Default to 24 hours
    
    print(f"[+] CloudWatch Metrics Collector")
    if namespace:
        print(f"    Namespace:   {namespace}")
    if dimensions:
        print(f"    Dimensions:  {dimensions}")
    print(f"    Hours:       {hours}")
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
        cw_client = _get_cloudwatch_client(args.region)
    except Exception as e:
        print(f"❌ Error getting CloudWatch client: {e}")
        return
    
    try:
        metrics_data = {
            "namespace": namespace,
            "dimensions": dimensions,
            "metrics": [],
            "metric_data": [],
        }
        
        # List metrics
        print("[+] Listing metrics...")
        list_kwargs = {}
        if namespace:
            list_kwargs["Namespace"] = namespace
        if dimensions:
            # Parse dimensions (format: Name1=Value1,Name2=Value2)
            dim_list = []
            for dim_pair in dimensions.split(","):
                if "=" in dim_pair:
                    name, value = dim_pair.split("=", 1)
                    dim_list.append({"Name": name.strip(), "Value": value.strip()})
            if dim_list:
                list_kwargs["Dimensions"] = dim_list
        
        paginator = cw_client.get_paginator("list_metrics")
        for page in paginator.paginate(**list_kwargs):
            for metric in page.get("Metrics", []):
                metric_info = {
                    "Namespace": metric.get("Namespace"),
                    "MetricName": metric.get("MetricName"),
                    "Dimensions": metric.get("Dimensions", []),
                }
                metrics_data["metrics"].append(metric_info)
        
        metrics_data["total_metrics"] = len(metrics_data["metrics"])
        print(f"    ✓ Found {metrics_data['total_metrics']} metric(s)")
        
        # Get metric data for recent period
        if metrics_data["metrics"]:
            print(f"[+] Collecting metric data from last {hours} hours...")
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=hours)
            
            # Group metrics by namespace for batch requests
            metrics_by_namespace = {}
            for metric in metrics_data["metrics"][:100]:  # Limit to 100 metrics to avoid too many requests
                ns = metric["Namespace"]
                if ns not in metrics_by_namespace:
                    metrics_by_namespace[ns] = []
                metrics_by_namespace[ns].append(metric)
            
            for ns, metric_list in metrics_by_namespace.items():
                for metric in metric_list:
                    try:
                        response = cw_client.get_metric_statistics(
                            Namespace=metric["Namespace"],
                            MetricName=metric["MetricName"],
                            Dimensions=metric.get("Dimensions", []),
                            StartTime=start_time,
                            EndTime=end_time,
                            Period=3600,  # 1 hour periods
                            Statistics=["Average", "Sum", "Maximum", "Minimum", "SampleCount"],
                        )
                        
                        if response.get("Datapoints"):
                            metrics_data["metric_data"].append({
                                "Namespace": metric["Namespace"],
                                "MetricName": metric["MetricName"],
                                "Dimensions": metric.get("Dimensions", []),
                                "Datapoints": [
                                    {
                                        "Timestamp": str(dp.get("Timestamp", "")),
                                        "Average": dp.get("Average"),
                                        "Sum": dp.get("Sum"),
                                        "Maximum": dp.get("Maximum"),
                                        "Minimum": dp.get("Minimum"),
                                        "SampleCount": dp.get("SampleCount"),
                                    }
                                    for dp in response.get("Datapoints", [])
                                ],
                            })
                    except ClientError as e:
                        print(f"      ⚠ Error getting data for {metric['MetricName']}: {e}")
            
            metrics_data["total_metric_data"] = len(metrics_data["metric_data"])
            print(f"    ✓ Collected data for {metrics_data['total_metric_data']} metric(s)")
        
        # Save single combined file
        filename = "cloudwatch_metrics.json"
        if namespace:
            safe_namespace = namespace.replace("/", "_").replace(" ", "_")
            filename = f"cloudwatch_metrics_{safe_namespace}.json"
        
        filepath = _save_json_file(output_dir, filename, metrics_data)
        if filepath:
            print(f"\n[✓] Saved metrics → {filepath}\n")
        
    except ClientError as e:
        print(f"❌ Error: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

