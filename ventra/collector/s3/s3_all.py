"""
S3 All Collector
Runs all S3 collectors for a bucket.
"""
from ventra.collector.s3.s3_bucket_info import run_s3_bucket_info
from ventra.collector.s3.s3_access import run_s3_access
from ventra.collector.s3.s3_objects import run_s3_objects
from ventra.collector.s3.s3_versions import run_s3_versions


def run_s3_all(args):
    """Run all S3 collectors for a bucket."""
    print(f"[+] S3 All Collectors")
    print(f"    Bucket:      {args.bucket}")
    print(f"    Prefix:      {getattr(args, 'prefix', '') if getattr(args, 'prefix', '') else '(all)'}")
    print(f"    Region:      {args.region}\n")
    
    collectors = [
        ("Bucket Info", run_s3_bucket_info),
        ("Access", run_s3_access),
        ("Objects", run_s3_objects),
        ("Versions", run_s3_versions),
    ]
    
    for name, collector_func in collectors:
        print(f"\n{'=' * 60}")
        print(f"[+] Running {name} Collector")
        print('=' * 60)
        try:
            collector_func(args)
        except Exception as e:
            print(f"❌ Error in {name} collector: {e}")
    
    print(f"\n{'=' * 60}")
    print("[✓] All S3 collectors completed")
    print('=' * 60 + "\n")

