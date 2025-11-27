"""
CloudWatch All Collector
Runs all CloudWatch collectors in sequence.
"""
from ventra.collector.cloudwatch.cloudwatch_log_groups import run_cloudwatch_log_groups
from ventra.collector.cloudwatch.cloudwatch_alarms import run_cloudwatch_alarms
from ventra.collector.cloudwatch.cloudwatch_events import run_cloudwatch_events
from ventra.collector.cloudwatch.cloudwatch_dashboards import run_cloudwatch_dashboards


def run_cloudwatch_all(args):
    """Run all CloudWatch collectors."""
    print(f"[+] CloudWatch All Collectors")
    print(f"    Region:      {args.region}\n")
    
    collectors = [
        ("Log Groups", run_cloudwatch_log_groups),
        ("Alarms", run_cloudwatch_alarms),
        ("Events", run_cloudwatch_events),
        ("Dashboards", run_cloudwatch_dashboards),
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
    print("[✓] All CloudWatch collectors completed")
    print('=' * 60 + "\n")

