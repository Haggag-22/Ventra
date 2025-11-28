"""
Normalization pipeline orchestrator.

Discovers and runs normalizers on collector data in a case directory.
"""

from pathlib import Path
from typing import List, Optional, Sequence
from datetime import datetime

from .core.context import NormalizationContext
from .core.base import NormalizationSummary
from .normalizers.cloudtrail import CloudTrailNormalizer
from .normalizers.ec2 import EC2Normalizer
from .normalizers.iam import IAMNormalizer
from .normalizers.dynamodb import DynamoDBNormalizer


# Registry of available normalizers
_NORMALIZERS = {
    "cloudtrail": CloudTrailNormalizer,
    "ec2": EC2Normalizer,
    "iam": IAMNormalizer,
    "dynamodb": DynamoDBNormalizer,
}


def run_pipeline(
    case_dir: str | Path,
    *,
    targets: Optional[Sequence[str]] = None,
    output_subdir: str = "normalized",
    profile: Optional[str] = None,
    account_id: Optional[str] = None,
    region: Optional[str] = None,
) -> List[NormalizationSummary]:
    """
    Run normalization pipeline on a case directory.
    
    Parameters
    ----------
    case_dir : str or Path
        Path to case directory containing collector output
    targets : list of str, optional
        Specific normalizers to run (e.g., ["cloudtrail"]). If None, runs all.
    output_subdir : str
        Subdirectory for normalized output (default: "normalized")
    profile : str, optional
        AWS profile name
    account_id : str, optional
        AWS account ID
    region : str, optional
        AWS region
    
    Returns
    -------
    list of NormalizationSummary
        Summary of each normalizer run
    """
    case_dir = Path(case_dir)
    
    if not case_dir.exists():
        raise ValueError(f"Case directory does not exist: {case_dir}")
    
    # Create context
    context = NormalizationContext.from_case_dir(
        case_dir=case_dir,
        output_subdir=output_subdir,
        profile=profile,
        account_id=account_id,
        region=region,
    )
    
    # Determine which normalizers to run
    if targets:
        missing = [t for t in targets if t not in _NORMALIZERS]
        if missing:
            raise ValueError(f"Unknown normalizer(s): {', '.join(sorted(missing))}")
        normalizer_names = targets
    else:
        normalizer_names = list(_NORMALIZERS.keys())
    
    # Run normalizers
    summaries: List[NormalizationSummary] = []
    
    print(f"\n[+] Normalization Pipeline")
    print(f"    Case Dir:   {case_dir}")
    print(f"    Output Dir: {context.output_dir}")
    print(f"    Normalizers: {', '.join(normalizer_names)}\n")
    
    for name in normalizer_names:
        print(f"[+] Running {name} normalizer...")
        normalizer_class = _NORMALIZERS[name]
        normalizer = normalizer_class()
        summary = normalizer.run(context)
        summaries.append(summary)
    
    # Print summary
    print(f"\n[+] Normalization Complete")
    total_records = sum(s.record_count for s in summaries)
    total_errors = sum(s.error_count for s in summaries)
    print(f"    Total Records: {total_records}")
    print(f"    Total Errors:  {total_errors}\n")
    
    return summaries


def run_from_args(args) -> List[NormalizationSummary]:
    """
    Convenience helper for CLI integration.
    
    Expected fields on args:
      * case_dir       (str)   - required
      * normalizers    (list)  - optional, subset of names
      * output_subdir  (str)   - optional
      * profile        (str)   - optional
      * account_id     (str)   - optional
      * region         (str)   - optional
    """
    case_dir = getattr(args, "case_dir", None)
    if not case_dir:
        raise ValueError("case_dir is required to run normalization")
    
    targets = getattr(args, "normalizers", None)
    output_subdir = getattr(args, "output_subdir", "normalized")
    profile = getattr(args, "profile", None)
    account_id = getattr(args, "account_id", None)
    region = getattr(args, "region", None)
    
    return run_pipeline(
        case_dir=case_dir,
        targets=targets,
        output_subdir=output_subdir,
        profile=profile,
        account_id=account_id,
        region=region,
    )
