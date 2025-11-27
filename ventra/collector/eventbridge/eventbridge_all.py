"""
EventBridge All Collector
Runs all EventBridge collectors in sequence.
"""
from ventra.collector.eventbridge.eventbridge_rules import run_eventbridge_rules
from ventra.collector.eventbridge.eventbridge_targets import run_eventbridge_targets
from ventra.collector.eventbridge.eventbridge_buses import run_eventbridge_buses


def run_eventbridge_all(args):
    """Run all EventBridge collectors."""
    print(f"[+] EventBridge All Collectors")
    print(f"    Region:      {args.region}\n")
    
    collectors = [
        ("Rules", run_eventbridge_rules),
        ("Targets", run_eventbridge_targets),
        ("Buses", run_eventbridge_buses),
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
    print("[✓] All EventBridge collectors completed")
    print('=' * 60 + "\n")

