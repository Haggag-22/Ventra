"""
Timeline Correlator.

Builds chronological timelines of events and activities.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from ..core.base import BaseCorrelator, CorrelationSummary
from ..core.context import CorrelationContext
from ..core.schema import CorrelationFields


class TimelineCorrelator(BaseCorrelator):
    """Builds timelines from events."""
    
    name = "timeline"
    
    def correlate(self, context: CorrelationContext) -> CorrelationSummary:
        """Build timelines from events."""
        # Load all normalized files
        all_files = list(context.normalized_dir.glob("*.json"))
        
        all_events = []
        
        for file_path in all_files:
            data = self.load_normalized_file(file_path)
            if not data:
                continue
            
            records = data.get("records", [])
            for record in records:
                # Only process events
                record_type = record.get("type", "")
                if record_type.startswith("aws.cloudtrail.event") or \
                   record_type.startswith("aws.cloudwatch.log_event") or \
                   record_type.startswith("aws.guardduty.finding") or \
                   record_type.startswith("aws.securityhub.finding"):
                    all_events.append(record)
        
        if not all_events:
            return CorrelationSummary(
                name=self.name,
                output_path=str(context.output_dir / "timelines.json"),
                records_processed=0,
                correlations_found=0,
            )
        
        # Build timelines by user, IP, and resource
        timelines_by_user = defaultdict(list)
        timelines_by_ip = defaultdict(list)
        timelines_by_resource = defaultdict(list)
        
        for event in all_events:
            # Extract timestamp
            event_time = event.get("event_time") or event.get("created_at")
            if not event_time:
                continue
            
            try:
                dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            except:
                continue
            
            # Group by user
            user_id = self._extract_user_id(event)
            if user_id:
                timelines_by_user[user_id].append((dt, event))
            
            # Group by IP
            ip = event.get("source_ip")
            if ip:
                timelines_by_ip[ip].append((dt, event))
            
            # Group by resource
            resource_id = event.get("resource_id") or event.get("arn")
            if resource_id:
                timelines_by_resource[resource_id].append((dt, event))
        
        # Sort timelines
        for user_id in timelines_by_user:
            timelines_by_user[user_id].sort(key=lambda x: x[0])
        for ip in timelines_by_ip:
            timelines_by_ip[ip].sort(key=lambda x: x[0])
        for resource_id in timelines_by_resource:
            timelines_by_resource[resource_id].sort(key=lambda x: x[0])
        
        # Add timeline data to events
        correlations_found = 0
        
        for event in all_events:
            if "correlations" not in event:
                event["correlations"] = {}
            
            timeline_data = {}
            
            # User timeline
            user_id = self._extract_user_id(event)
            if user_id and user_id in timelines_by_user:
                user_timeline = timelines_by_user[user_id]
                if user_timeline:
                    first_seen = user_timeline[0][0]
                    last_seen = user_timeline[-1][0]
                    timeline_data[CorrelationFields.FIRST_SEEN] = first_seen.isoformat() + "Z"
                    timeline_data[CorrelationFields.LAST_SEEN] = last_seen.isoformat() + "Z"
                    timeline_data[CorrelationFields.TOTAL_EVENTS] = len(user_timeline)
            
            # IP timeline
            ip = event.get("source_ip")
            if ip and ip in timelines_by_ip:
                ip_timeline = timelines_by_ip[ip]
                if ip_timeline:
                    if CorrelationFields.FIRST_SEEN not in timeline_data:
                        first_seen = ip_timeline[0][0]
                        last_seen = ip_timeline[-1][0]
                        timeline_data[CorrelationFields.FIRST_SEEN] = first_seen.isoformat() + "Z"
                        timeline_data[CorrelationFields.LAST_SEEN] = last_seen.isoformat() + "Z"
                        timeline_data[CorrelationFields.TOTAL_EVENTS] = len(ip_timeline)
            
            if timeline_data:
                event["correlations"][CorrelationFields.TIMELINE] = timeline_data
                correlations_found += 1
        
        # Save timeline data
        output_data = {
            "correlator": self.name,
            "correlated_at": datetime.utcnow().isoformat() + "Z",
            "total_events": len(all_events),
            "timelines_by_user": len(timelines_by_user),
            "timelines_by_ip": len(timelines_by_ip),
            "timelines_by_resource": len(timelines_by_resource),
            "correlations_found": correlations_found,
        }
        
        output_path = self.save_correlated_file(context, output_data, "timelines.json")
        
        return CorrelationSummary(
            name=self.name,
            output_path=str(output_path),
            records_processed=len(all_events),
            correlations_found=correlations_found,
        )
    
    def _extract_user_id(self, event: Dict[str, Any]) -> Optional[str]:
        """Extract user identifier from event."""
        user_identity = event.get("user_identity", {})
        if isinstance(user_identity, dict):
            return user_identity.get("principalId") or user_identity.get("arn")
        return None

