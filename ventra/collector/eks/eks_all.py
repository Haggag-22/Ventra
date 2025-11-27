"""
EKS All Collector
Runs all EKS collectors for a cluster.
"""
from ventra.collector.eks.eks_nodegroups import run_eks_nodegroups
from ventra.collector.eks.eks_fargate import run_eks_fargate
from ventra.collector.eks.eks_addons import run_eks_addons
from ventra.collector.eks.eks_logs_config import run_eks_logs_config
from ventra.collector.eks.eks_oidc import run_eks_oidc
from ventra.collector.eks.eks_controlplane_logs import run_eks_controlplane_logs
from ventra.collector.eks.eks_security import run_eks_security
from ventra.collector.eks.eks_networking import run_eks_networking


def run_eks_all(args):
    """Run all EKS collectors for a cluster."""
    cluster_name = args.cluster
    print(f"[+] EKS All Collectors")
    print(f"    Cluster:     {cluster_name}")
    print(f"    Region:      {args.region}\n")
    
    collectors = [
        ("Nodegroups", run_eks_nodegroups),
        ("Fargate", run_eks_fargate),
        ("Addons", run_eks_addons),
        ("Logs Config", run_eks_logs_config),
        ("OIDC", run_eks_oidc),
        ("Control Plane Logs", run_eks_controlplane_logs),
        ("Security", run_eks_security),
        ("Networking", run_eks_networking),
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
    print("[✓] All EKS collectors completed")
    print('=' * 60 + "\n")

