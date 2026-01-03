"""
Event-to-Event Correlator.

Links events together based on common attributes like user identity, IP address, etc.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
import json

from ..core.base import BaseCorrelator, CorrelationSummary
from ..core.context import CorrelationContext
from ..core.schema import CorrelationFields, RelationshipTypes


class EventToEventCorrelator(BaseCorrelator):
    """Correlates events to other events based on common attributes."""
    
    name = "event_to_event"
    
    def correlate(self, context: CorrelationContext) -> CorrelationSummary:
        """Correlate events to other events."""
        # Load all normalized event files
        event_files = context.normalized_dir.glob("*.json")
        
        all_events = []
        for file_path in event_files:
            data = self.load_normalized_file(file_path)
            if not data:
                continue
            
            # Extract events from normalized files
            records = data.get("records", [])
            for record in records:
                # Only process event-type records
                if record.get("type", "").startswith("aws.cloudtrail.event") or \
                   record.get("type", "").startswith("aws.cloudwatch.log_event"):
                    all_events.append(record)
        
        if not all_events:
            return CorrelationSummary(
                name=self.name,
                output_path=str(context.output_dir / "event_correlations.json"),
                records_processed=0,
                correlations_found=0,
            )
        
        # Build indexes for fast lookup
        events_by_user = {}
        events_by_ip = {}
        events_by_access_key = {}
        events_by_time = []
        
        for event in all_events:
            # Index by user identity
            user_id = self._extract_user_id(event)
            if user_id:
                if user_id not in events_by_user:
                    events_by_user[user_id] = []
                events_by_user[user_id].append(event)
            
            # Index by IP
            ip = event.get("source_ip")
            if ip:
                if ip not in events_by_ip:
                    events_by_ip[ip] = []
                events_by_ip[ip].append(event)
            
            # Index by access key
            access_key = self._extract_access_key(event)
            if access_key:
                if access_key not in events_by_access_key:
                    events_by_access_key[access_key] = []
                events_by_access_key[access_key].append(event)
            
            # Index by time
            event_time = event.get("event_time") or event.get("created_at")
            if event_time:
                try:
                    dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                    events_by_time.append((dt, event))
                except:
                    pass
        
        # Sort by time
        events_by_time.sort(key=lambda x: x[0])
        
        # Correlate events (optimized - limit comparisons per event)
        correlations_found = 0
        errors = []
        MAX_RELATED_EVENTS = 20  # Limit related events per correlation type
        MAX_TOTAL_RELATED = 50   # Maximum total related events per event
        
        print(f"      Processing {len(all_events):,} events...")
        
        for idx, event in enumerate(all_events):
            if idx > 0 and idx % 5000 == 0:
                print(f"      Processed {idx:,}/{len(all_events):,} events...")
            
            if "correlations" not in event:
                event["correlations"] = {}
            
            related_events = []
            seen_event_ids = set()  # Track already added events to avoid duplicates
            
            # Find events by same user (limit to closest in time)
            user_id = self._extract_user_id(event)
            if user_id and user_id in events_by_user:
                user_events = events_by_user[user_id]
                # Only process if not too many events (avoid O(n²) explosion)
                if len(user_events) <= 1000:  # Skip if user has >1000 events
                    # Sort by time proximity and take closest
                    event_time = self._parse_time(event.get("event_time") or event.get("created_at"))
                    if event_time:
                        user_events_with_time = [
                            (self._parse_time(e.get("event_time") or e.get("created_at")), e)
                            for e in user_events
                            if e.get("event_id") != event.get("event_id")
                        ]
                        user_events_with_time.sort(key=lambda x: abs((x[0] - event_time).total_seconds()) if x[0] else float('inf'))
                        
                        for _, related in user_events_with_time[:MAX_RELATED_EVENTS]:
                            if related.get("event_id") not in seen_event_ids:
                                time_diff = self._time_diff(event, related)
                                related_events.append({
                                    "event_id": related.get("event_id"),
                                    "relationship": RelationshipTypes.SAME_USER,
                                    CorrelationFields.TIME_DIFF_SECONDS: time_diff,
                                    CorrelationFields.RELATIONSHIP_CONFIDENCE: 0.9,
                                })
                                seen_event_ids.add(related.get("event_id"))
            
            # Find events by same IP (limit to closest in time)
            ip = event.get("source_ip")
            if ip and ip in events_by_ip:
                ip_events = events_by_ip[ip]
                if len(ip_events) <= 1000:  # Skip if IP has >1000 events
                    event_time = self._parse_time(event.get("event_time") or event.get("created_at"))
                    if event_time:
                        ip_events_with_time = [
                            (self._parse_time(e.get("event_time") or e.get("created_at")), e)
                            for e in ip_events
                            if e.get("event_id") != event.get("event_id") and e.get("event_id") not in seen_event_ids
                        ]
                        ip_events_with_time.sort(key=lambda x: abs((x[0] - event_time).total_seconds()) if x[0] else float('inf'))
                        
                        for _, related in ip_events_with_time[:MAX_RELATED_EVENTS]:
                            time_diff = self._time_diff(event, related)
                            related_events.append({
                                "event_id": related.get("event_id"),
                                "relationship": RelationshipTypes.SAME_IP,
                                CorrelationFields.TIME_DIFF_SECONDS: time_diff,
                                CorrelationFields.RELATIONSHIP_CONFIDENCE: 0.85,
                            })
                            seen_event_ids.add(related.get("event_id"))
            
            # Find events by same access key (limit to closest in time)
            access_key = self._extract_access_key(event)
            if access_key and access_key in events_by_access_key:
                key_events = events_by_access_key[access_key]
                if len(key_events) <= 1000:  # Skip if access key has >1000 events
                    event_time = self._parse_time(event.get("event_time") or event.get("created_at"))
                    if event_time:
                        key_events_with_time = [
                            (self._parse_time(e.get("event_time") or e.get("created_at")), e)
                            for e in key_events
                            if e.get("event_id") != event.get("event_id") and e.get("event_id") not in seen_event_ids
                        ]
                        key_events_with_time.sort(key=lambda x: abs((x[0] - event_time).total_seconds()) if x[0] else float('inf'))
                        
                        for _, related in key_events_with_time[:MAX_RELATED_EVENTS]:
                            time_diff = self._time_diff(event, related)
                            related_events.append({
                                "event_id": related.get("event_id"),
                                "relationship": RelationshipTypes.SAME_ACCESS_KEY,
                                CorrelationFields.TIME_DIFF_SECONDS: time_diff,
                                CorrelationFields.RELATIONSHIP_CONFIDENCE: 0.95,
                            })
                            seen_event_ids.add(related.get("event_id"))
            
            # Limit total related events
            if related_events:
                event["correlations"][CorrelationFields.RELATED_EVENTS] = related_events[:MAX_TOTAL_RELATED]
                correlations_found += len(related_events[:MAX_TOTAL_RELATED])
        
        # Save summary (don't update original files for large datasets - too slow)
        # Instead, save correlations to a separate file that can be merged later
        events_with_correlations = sum(1 for e in all_events if e.get("correlations", {}).get(CorrelationFields.RELATED_EVENTS))
        
        output_data = {
            "correlator": self.name,
            "correlated_at": datetime.utcnow().isoformat() + "Z",
            "total_events": len(all_events),
            "correlations_found": correlations_found,
            "events_with_correlations": events_with_correlations,
            "note": "Correlations are stored separately. Use merge_correlations() to merge into normalized files.",
        }
        
        output_path = self.save_correlated_file(context, output_data, "event_correlations_summary.json")
        
        # Save a sample of correlated events (first 1000) for inspection
        if events_with_correlations > 0:
            sample_events = [e for e in all_events if e.get("correlations", {}).get(CorrelationFields.RELATED_EVENTS)][:1000]
            sample_data = {
                "correlator": self.name,
                "correlated_at": datetime.utcnow().isoformat() + "Z",
                "total_events": len(all_events),
                "sample_size": len(sample_events),
                "events": sample_events,
            }
            self.save_correlated_file(context, sample_data, "event_correlations_sample.json")
        
        return CorrelationSummary(
            name=self.name,
            output_path=str(output_path),
            records_processed=len(all_events),
            correlations_found=correlations_found,
            error_count=len(errors),
            errors=errors,
        )
    
    def _extract_user_id(self, event: Dict[str, Any]) -> Optional[str]:
        """Extract user identifier from event."""
        user_identity = event.get("user_identity", {})
        if isinstance(user_identity, dict):
            return user_identity.get("principalId") or user_identity.get("arn")
        return None
    
    def _extract_access_key(self, event: Dict[str, Any]) -> Optional[str]:
        """Extract access key from event."""
        user_identity = event.get("user_identity", {})
        if isinstance(user_identity, dict):
            return user_identity.get("accessKeyId")
        return None
    
    def _parse_time(self, time_str: Optional[str]) -> Optional[datetime]:
        """Parse time string to datetime object."""
        if not time_str:
            return None
        try:
            return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
        except:
            return None
    
    def _time_diff(self, event1: Dict[str, Any], event2: Dict[str, Any]) -> Optional[int]:
        """Calculate time difference in seconds between two events."""
        time1_str = event1.get("event_time") or event1.get("created_at")
        time2_str = event2.get("event_time") or event2.get("created_at")
        
        if not time1_str or not time2_str:
            return None
        
        dt1 = self._parse_time(time1_str)
        dt2 = self._parse_time(time2_str)
        
        if dt1 and dt2:
            return abs(int((dt1 - dt2).total_seconds()))
        return None

