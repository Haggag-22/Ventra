"""
Pattern Detection Correlator.

Detects attack patterns and suspicious activities.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from ..core.base import BaseCorrelator, CorrelationSummary
from ..core.context import CorrelationContext
from ..core.schema import CorrelationFields


class PatternDetectionCorrelator(BaseCorrelator):
    """Detects attack patterns and suspicious activities."""
    
    name = "pattern_detection"
    
    def correlate(self, context: CorrelationContext) -> CorrelationSummary:
        """Detect patterns in events."""
        # Load all normalized files
        all_files = list(context.normalized_dir.glob("*.json"))
        
        all_events = []
        
        for file_path in all_files:
            data = self.load_normalized_file(file_path)
            if not data:
                continue
            
            records = data.get("records", [])
            for record in records:
                record_type = record.get("type", "")
                if record_type.startswith("aws.cloudtrail.event") or \
                   record_type.startswith("aws.guardduty.finding") or \
                   record_type.startswith("aws.securityhub.finding"):
                    all_events.append(record)
        
        if not all_events:
            return CorrelationSummary(
                name=self.name,
                output_path=str(context.output_dir / "patterns.json"),
                records_processed=0,
                correlations_found=0,
            )
        
        # Detect patterns
        correlations_found = 0
        
        for event in all_events:
            if "correlations" not in event:
                event["correlations"] = {}
            
            patterns = {}
            
            # Privilege escalation detection
            if self._detect_privilege_escalation(event, all_events):
                patterns[CorrelationFields.PRIVILEGE_ESCALATION] = True
            
            # Reconnaissance detection
            if self._detect_reconnaissance(event, all_events):
                patterns[CorrelationFields.RECONNAISSANCE] = True
            
            # Geographic anomaly detection
            if self._detect_geographic_anomaly(event):
                patterns[CorrelationFields.GEOGRAPHIC_ANOMALY] = True
            
            # Sustained activity detection
            if self._detect_sustained_activity(event, all_events):
                patterns[CorrelationFields.SUSTAINED_ACTIVITY] = True
            
            if patterns:
                event["correlations"][CorrelationFields.PATTERNS] = patterns
                correlations_found += 1
        
        # Save pattern data
        output_data = {
            "correlator": self.name,
            "correlated_at": datetime.utcnow().isoformat() + "Z",
            "total_events": len(all_events),
            "correlations_found": correlations_found,
        }
        
        output_path = self.save_correlated_file(context, output_data, "patterns.json")
        
        return CorrelationSummary(
            name=self.name,
            output_path=str(output_path),
            records_processed=len(all_events),
            correlations_found=correlations_found,
        )
    
    def _detect_privilege_escalation(self, event: Dict[str, Any], all_events: List[Dict[str, Any]]) -> bool:
        """Detect privilege escalation patterns."""
        # Check if root user
        user_identity = event.get("user_identity", {})
        if isinstance(user_identity, dict):
            if user_identity.get("type") == "Root":
                return True
            
            # Check for CreateUser -> AttachUserPolicy pattern
            event_name = event.get("event_name", "")
            if event_name in ["CreateUser", "CreateRole"]:
                # Look for subsequent policy attachments
                event_time = event.get("event_time")
                if event_time:
                    for other_event in all_events:
                        other_time = other_event.get("event_time")
                        if other_time and other_time > event_time:
                            other_name = other_event.get("event_name", "")
                            if "Attach" in other_name and "Policy" in other_name:
                                return True
        
        return False
    
    def _detect_reconnaissance(self, event: Dict[str, Any], all_events: List[Dict[str, Any]]) -> bool:
        """Detect reconnaissance patterns."""
        event_name = event.get("event_name", "")
        
        # List/Describe/Get operations across multiple services
        recon_verbs = ["List", "Describe", "Get", "Query"]
        if any(event_name.startswith(verb) for verb in recon_verbs):
            # Check if same user/IP has many list operations
            user_id = self._extract_user_id(event)
            ip = event.get("source_ip")
            
            if user_id or ip:
                count = 0
                for other_event in all_events:
                    other_name = other_event.get("event_name", "")
                    if any(other_name.startswith(verb) for verb in recon_verbs):
                        if (user_id and self._extract_user_id(other_event) == user_id) or \
                           (ip and other_event.get("source_ip") == ip):
                            count += 1
                
                if count > 10:  # Threshold
                    return True
        
        return False
    
    def _detect_geographic_anomaly(self, event: Dict[str, Any]) -> bool:
        """Detect geographic anomalies."""
        # Check metadata for geographic info
        metadata = event.get("metadata", {})
        if isinstance(metadata, dict):
            # Check GuardDuty finding for geographic info
            service = metadata.get("service", {})
            if isinstance(service, dict):
                action = service.get("Action", {})
                if isinstance(action, dict):
                    api_call = action.get("AwsApiCallAction", {})
                    if isinstance(api_call, dict):
                        remote_ip = api_call.get("RemoteIpDetails", {})
                        if isinstance(remote_ip, dict):
                            country = remote_ip.get("Country", {})
                            if isinstance(country, dict):
                                country_name = country.get("CountryName")
                                # Flag non-US countries as potential anomaly
                                if country_name and country_name not in ["United States", "US"]:
                                    return True
        
        return False
    
    def _detect_sustained_activity(self, event: Dict[str, Any], all_events: List[Dict[str, Any]]) -> bool:
        """Detect sustained activity patterns."""
        user_id = self._extract_user_id(event)
        ip = event.get("source_ip")
        
        if user_id or ip:
            # Count events from same user/IP
            count = 0
            for other_event in all_events:
                if (user_id and self._extract_user_id(other_event) == user_id) or \
                   (ip and other_event.get("source_ip") == ip):
                    count += 1
            
            # If more than 100 events, consider it sustained
            if count > 100:
                return True
        
        return False
    
    def _extract_user_id(self, event: Dict[str, Any]) -> Optional[str]:
        """Extract user identifier from event."""
        user_identity = event.get("user_identity", {})
        if isinstance(user_identity, dict):
            return user_identity.get("principalId") or user_identity.get("arn")
        return None

