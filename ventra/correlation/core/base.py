"""
Base correlator class and common utilities.

All service-specific correlators should inherit from BaseCorrelator.
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
from datetime import datetime

from .context import CorrelationContext


class CorrelationError(Exception):
    """Error during correlation of records."""
    
    def __init__(self, message: str, record: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.record = record


class CorrelationSummary:
    """Summary of correlation run."""
    
    def __init__(
        self,
        name: str,
        output_path: str,
        records_processed: int = 0,
        correlations_found: int = 0,
        error_count: int = 0,
        errors: Optional[List[str]] = None,
    ):
        self.name = name
        self.output_path = output_path
        self.records_processed = records_processed
        self.correlations_found = correlations_found
        self.error_count = error_count
        self.errors = errors or []
    
    def __repr__(self):
        return (
            f"CorrelationSummary(name={self.name!r}, "
            f"records={self.records_processed}, "
            f"correlations={self.correlations_found}, "
            f"errors={self.error_count})"
        )


class BaseCorrelator(ABC):
    """
    Abstract base class for all correlators.
    
    Subclasses must implement:
    - name: str (class attribute) - Unique identifier for this correlator
    - correlate(context) - Perform correlation and add correlation data to records
    """
    
    # Subclasses must set this
    name: str = ""
    
    def __init__(self):
        if not self.name:
            raise ValueError(f"{self.__class__.__name__} must set 'name' class attribute")
    
    @abstractmethod
    def correlate(self, context: CorrelationContext) -> CorrelationSummary:
        """
        Perform correlation and add correlation data to records.
        
        Parameters
        ----------
        context : CorrelationContext
            Correlation context with case_dir, normalized_dir, etc.
        
        Returns
        -------
        CorrelationSummary
            Summary of correlation run
        """
        pass
    
    def load_normalized_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Load a normalized JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"    ⚠ Error loading {file_path.name}: {e}")
            return None
    
    def save_correlated_file(self, context: CorrelationContext, data: Dict[str, Any], filename: str) -> Path:
        """Save correlated data to a JSON file."""
        output_path = context.output_dir / filename
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            return output_path
        except Exception as e:
            raise CorrelationError(f"Error saving {filename}: {e}")
    
    def find_normalized_files(self, context: CorrelationContext, patterns: List[str]) -> List[Path]:
        """Find normalized JSON files matching patterns."""
        if not context.normalized_dir.exists():
            return []
        
        found = []
        for pattern in patterns:
            # Simple glob matching
            for file_path in context.normalized_dir.glob(pattern):
                if file_path.is_file() and file_path.suffix == ".json":
                    found.append(file_path)
        
        return sorted(set(found))

