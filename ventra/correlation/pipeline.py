"""
Correlation pipeline orchestrator.

Runs all correlators on normalized data in a case directory.
"""

from pathlib import Path
from typing import List, Union
from datetime import datetime

from .core.context import CorrelationContext
from .core.base import CorrelationSummary
from .correlators.event_to_event import EventToEventCorrelator
from .correlators.event_to_resource import EventToResourceCorrelator
from .correlators.resource_to_resource import ResourceToResourceCorrelator
from .correlators.timeline import TimelineCorrelator


# Registry of available correlators
_CORRELATORS = {
    "event_to_event": EventToEventCorrelator,
    "event_to_resource": EventToResourceCorrelator,
    "resource_to_resource": ResourceToResourceCorrelator,
    "timeline": TimelineCorrelator,
}


def run_correlation_pipeline(
    case_dir: Union[str, Path],
) -> List[CorrelationSummary]:
    """
    Run correlation pipeline on normalized data.
    
    Parameters
    ----------
    case_dir : str or Path
        Case directory containing normalized data
    Returns
    -------
    list of CorrelationSummary
        Summary of each correlator run
    """
    case_dir = Path(case_dir)
    
    if not case_dir.exists():
        raise ValueError(f"Case directory does not exist: {case_dir}")
    
    # Create correlation context
    context = CorrelationContext(case_dir=case_dir)
    
    # Check if normalized data exists
    if not context.normalized_dir.exists():
        print(f"    ⚠ No normalized data found in {context.normalized_dir}")
        return []
    
    # Always run all correlators
    correlators_to_run = [cls() for cls in _CORRELATORS.values()]
    
    # Run correlators
    summaries = []
    print(f"\n    Running {len(correlators_to_run)} correlator(s)...")
    
    for correlator in correlators_to_run:
        try:
            print(f"    → {correlator.name}...")
            summary = correlator.correlate(context)
            summaries.append(summary)
            print(
                f"      ✓ Processed {summary.records_processed} record(s), "
                f"found {summary.correlations_found} correlation(s)"
            )
        except Exception as e:
            print(f"      ✗ Error: {e}")
            summaries.append(CorrelationSummary(
                name=correlator.name,
                output_path="",
                records_processed=0,
                correlations_found=0,
                error_count=1,
                errors=[str(e)],
            ))
    
    return summaries

