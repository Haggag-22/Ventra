"""
Normalization context for passing metadata and paths to normalizers.
"""

from pathlib import Path
from typing import Optional, Dict, Any


class NormalizationContext:
    """
    Context object passed to normalizers containing case directory,
    output paths, and optional metadata.
    """
    
    def __init__(
        self,
        case_dir: str | Path,
        output_dir: str | Path,
        profile: Optional[str] = None,
        account_id: Optional[str] = None,
        region: Optional[str] = None,
        extras: Optional[Dict[str, Any]] = None,
    ):
        self.case_dir = Path(case_dir)
        self.output_dir = Path(output_dir)
        self.profile = profile
        self.account_id = account_id
        self.region = region
        self.extras = extras or {}
    
    @classmethod
    def from_case_dir(
        cls,
        case_dir: str | Path,
        output_subdir: str = "normalized",
        profile: Optional[str] = None,
        account_id: Optional[str] = None,
        region: Optional[str] = None,
        extras: Optional[Dict[str, Any]] = None,
    ) -> "NormalizationContext":
        """
        Create context from case directory.
        
        Parameters
        ----------
        case_dir : str or Path
            Path to case directory containing collector output
        output_subdir : str
            Subdirectory within case_dir for normalized output (default: "normalized")
        profile : str, optional
            AWS profile name
        account_id : str, optional
            AWS account ID
        region : str, optional
            AWS region
        extras : dict, optional
            Additional metadata
        """
        case_dir = Path(case_dir)
        output_dir = case_dir / output_subdir
        
        return cls(
            case_dir=case_dir,
            output_dir=output_dir,
            profile=profile,
            account_id=account_id,
            region=region,
            extras=extras,
        )

