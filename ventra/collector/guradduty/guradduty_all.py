"""
GuardDuty All Collector
Runs all GuardDuty collectors in sequence.
"""
from ventra.collector.guradduty.guradduty_detectors import run_guradduty_detectors
from ventra.collector.guradduty.guradduty_findings import run_guradduty_findings
from ventra.collector.guradduty.guradduty_malware import run_guradduty_malware


def run_guradduty_all(args):
    """Run all GuardDuty collectors."""
    print(f"[+] GuardDuty All Collectors")
    print(f"    Region:      {args.region}\n")
    
    collectors = [
        ("Detectors", run_guradduty_detectors),
        ("Findings", run_guradduty_findings),
        ("Malware", run_guradduty_malware),
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
    print("[✓] All GuardDuty collectors completed")
    print('=' * 60 + "\n")

