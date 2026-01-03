"""
Correlation context - provides case directory and metadata for correlation.
"""

from pathlib import Path
from typing import Optional


class CorrelationContext:
    """Context for correlation operations."""
    
    def __init__(
        self,
        case_dir: Path,
        normalized_dir: Optional[Path] = None,
    ):
        self.case_dir = Path(case_dir)
        
        # Default normalized directory
        if normalized_dir:
            self.normalized_dir = Path(normalized_dir)
        else:
            self.normalized_dir = self.case_dir / "normalized"
        
        # Output directory for correlated data
        self.output_dir = self.case_dir / "correlated"
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def __repr__(self):
        return (
            f"CorrelationContext(case_dir={self.case_dir!r}, "
            f"normalized_dir={self.normalized_dir!r}, "
            f"output_dir={self.output_dir!r})"
        )

