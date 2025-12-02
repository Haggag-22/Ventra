"""
Base normalizer class and common utilities.

All service-specific normalizers should inherit from BaseNormalizer
and implement the required abstract methods.
"""

import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
from datetime import datetime

from .schema import Fields


class NormalizationError(Exception):
    """Error during normalization of a specific record."""
    
    def __init__(self, message: str, record: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.record = record


class NormalizationSummary:
    """Summary of normalization run."""
    
    def __init__(
        self,
        name: str,
        output_path: str,
        record_count: int = 0,
        error_count: int = 0,
        errors: Optional[List[str]] = None,
    ):
        self.name = name
        self.output_path = output_path
        self.record_count = record_count
        self.error_count = error_count
        self.errors = errors or []
    
    def __repr__(self):
        return (
            f"NormalizationSummary(name={self.name!r}, "
            f"records={self.record_count}, errors={self.error_count})"
        )


class BaseNormalizer(ABC):
    """
    Abstract base class for all normalizers.
    
    Subclasses must implement:
    - name: str (class attribute) - Unique identifier for this normalizer
    - load_raw(context) -> Iterator[Dict] - Load raw data from collector files
    - normalize_record(raw, context) -> Optional[Dict] - Normalize a single record
    
    The base class provides:
    - File discovery utilities
    - Error handling
    - JSON saving
    - Run workflow orchestration
    """
    
    # Subclasses must set this
    name: str = ""
    
    def __init__(self):
        if not self.name:
            raise ValueError(f"{self.__class__.__name__} must set 'name' class attribute")
    
    @abstractmethod
    def load_raw(self, context: "NormalizationContext") -> Iterator[Dict[str, Any]]:
        """
        Load raw data from collector output files.
        
        This method should:
        1. Discover relevant JSON files in the case directory
        2. Parse JSON files
        3. Yield individual records (dicts) that need normalization
        
        Parameters
        ----------
        context : NormalizationContext
            Context with case_dir, output_dir, etc.
        
        Yields
        ------
        dict
            Raw record dictionaries from collector output
        """
        pass
    
    @abstractmethod
    def normalize_record(
        self, raw: Dict[str, Any], context: "NormalizationContext"
    ) -> Optional[Dict[str, Any]]:
        """
        Normalize a single raw record into standardized schema.
        
        Parameters
        ----------
        raw : dict
            Raw record from collector
        context : NormalizationContext
            Context with case_dir, output_dir, metadata
        
        Returns
        -------
        dict or None
            Normalized record dict following schema, or None to skip
        """
        pass
    
    def find_collector_files(
        self,
        context: "NormalizationContext",
        patterns: List[str],
        subdirs: Optional[List[str]] = None,
    ) -> List[Path]:
        """
        Find collector JSON files matching patterns.
        
        Parameters
        ----------
        context : NormalizationContext
            Normalization context
        patterns : list of str
            Filename patterns to match (e.g., ["s3_*_all.json", "s3_bucket_info.json"])
        subdirs : list of str, optional
            Subdirectories within case_dir to search (e.g., ["events", "resources"]).
            If None, searches in both "events" and "resources" subdirectories.
        
        Returns
        -------
        list of Path
            Matching file paths
        """
        case_dir = Path(context.case_dir)
        
        # Default to searching both events and resources subdirectories
        if subdirs is None:
            subdirs = ["events", "resources"]
        
        found = []
        for subdir in subdirs:
            search_dir = case_dir / subdir
            
            if not search_dir.exists():
                continue
            
            for pattern in patterns:
                # Simple glob matching
                for file_path in search_dir.glob(pattern):
                    if file_path.is_file() and file_path.suffix == ".json":
                        found.append(file_path)
        
        return sorted(set(found))
    
    def load_json_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Load and parse a JSON file.
        
        Parameters
        ----------
        file_path : Path
            Path to JSON file
        
        Returns
        -------
        dict or None
            Parsed JSON data, or None if error
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"    ⚠ Error loading {file_path}: {e}")
            return None
    
    def _sort_records_by_timestamp(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sort records by timestamp for chronological ordering.
        
        Checks multiple timestamp fields in priority order:
        1. event_time (for events like CloudTrail)
        2. created_at (for resources)
        3. last_modified (for S3 objects, etc.)
        4. updated_at (for resources with updates)
        
        Records without timestamps are placed at the end.
        
        Parameters
        ----------
        records : list of dict
            Normalized records to sort
        
        Returns
        -------
        list of dict
            Records sorted chronologically (oldest first)
        """
        def get_timestamp(record: Dict[str, Any]) -> str:
            # Priority order: event_time > created_at > last_modified > updated_at
            timestamp = (
                record.get(Fields.EVENT_TIME) or
                record.get(Fields.CREATED_AT) or
                record.get(Fields.LAST_MODIFIED) or
                record.get(Fields.UPDATED_AT)
            )
            if timestamp:
                return timestamp
            # Put records without timestamps at the end
            return "9999-12-31T23:59:59Z"
        
        return sorted(records, key=get_timestamp)
    
    def save_normalized(
        self,
        context: "NormalizationContext",
        records: List[Dict[str, Any]],
        output_filename: Optional[str] = None,
    ) -> Path:
        """
        Save normalized records to JSON file.
        
        Records are automatically sorted by timestamp (event_time or created_at)
        for chronological timeline analysis.
        
        Parameters
        ----------
        context : NormalizationContext
            Normalization context
        records : list of dict
            Normalized records
        output_filename : str, optional
            Output filename (defaults to "{name}.json")
        
        Returns
        -------
        Path
            Path to saved file
        """
        output_dir = Path(context.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        filename = output_filename or f"{self.name}.json"
        output_path = output_dir / filename
        
        # Sort records by timestamp for chronological timeline
        sorted_records = self._sort_records_by_timestamp(records)
        
        output_data = {
            "normalizer": self.name,
            "normalized_at": datetime.utcnow().isoformat() + "Z",
            "record_count": len(sorted_records),
            "records": sorted_records,
        }
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, default=str)
        
        return output_path
    
    def run(self, context: "NormalizationContext") -> NormalizationSummary:
        """
        Run the normalization workflow.
        
        This method:
        1. Calls load_raw() to get raw records
        2. Calls normalize_record() for each record
        3. Collects errors
        4. Saves normalized output
        5. Returns summary
        
        Parameters
        ----------
        context : NormalizationContext
            Normalization context
        
        Returns
        -------
        NormalizationSummary
            Summary of normalization run
        """
        records: List[Dict[str, Any]] = []
        errors: List[str] = []
        
        try:
            # Load raw data
            raw_records = list(self.load_raw(context))
            
            if not raw_records:
                print(f"    ⚠ No raw data found for {self.name}")
                output_path = self.save_normalized(context, [])
                return NormalizationSummary(
                    name=self.name,
                    output_path=str(output_path),
                    record_count=0,
                    error_count=0,
                )
            
            # Normalize each record
            for idx, raw in enumerate(raw_records):
                try:
                    normalized = self.normalize_record(raw, context)
                    if normalized is not None:
                        records.append(normalized)
                except Exception as e:
                    error_msg = f"Record {idx}: {str(e)}"
                    errors.append(error_msg)
                    print(f"    ⚠ {error_msg}")
            
            # Save normalized output
            output_path = self.save_normalized(context, records)
            
            print(
                f"    ✓ Normalized {len(records)} record(s) → {output_path.name} "
                f"({len(errors)} error(s))"
            )
            
            return NormalizationSummary(
                name=self.name,
                output_path=str(output_path),
                record_count=len(records),
                error_count=len(errors),
                errors=errors,
            )
        
        except Exception as e:
            error_msg = f"Fatal error in {self.name}: {str(e)}"
            print(f"    ❌ {error_msg}")
            errors.append(error_msg)
            
            # Try to save empty output
            try:
                output_path = self.save_normalized(context, [])
            except Exception:
                output_path = Path(context.output_dir) / f"{self.name}.json"
            
            return NormalizationSummary(
                name=self.name,
                output_path=str(output_path),
                record_count=0,
                error_count=len(errors),
                errors=errors,
            )


# Forward reference for type hints
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .context import NormalizationContext

