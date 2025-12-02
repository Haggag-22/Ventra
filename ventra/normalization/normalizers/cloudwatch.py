"""
CloudWatch resource normalizer.

Normalizes CloudWatch log groups, log streams, log events, and alarms from collector output.
"""

import json
from typing import Dict, Iterator, Optional, Any, List
from pathlib import Path

from ..core.base import BaseNormalizer
from ..core.context import NormalizationContext
from ..core.schema import Fields, ResourceTypes
from ..core.utils import (
    normalize_timestamp,
    generate_resource_id,
    generate_event_id,
    parse_arn,
    extract_account_id_from_arn,
    extract_region_from_arn,
)


class CloudWatchNormalizer(BaseNormalizer):
    """
    Normalizes CloudWatch resources from collector JSON files.
    
    Handles:
    - cloudwatch_all.json (from cloudwatch_all collector)
    """
    
    name = "cloudwatch"
    
    def load_raw(self, context: NormalizationContext) -> Iterator[Dict[str, Any]]:
        """Load CloudWatch data from collector JSON files."""
        # CloudWatch log groups are in events/ subdirectory
        patterns = ["cloudwatch_log_group_*.json"]
        files = self.find_collector_files(context, patterns, subdirs=["events"])
        
        if not files:
            return
        
        for file_path in files:
            data = self.load_json_file(file_path)
            if not data:
                continue
            
            yield data
    
    def normalize_record(
        self, raw: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize CloudWatch resources - returns None, handled in custom run()."""
        return None
    
    def run(self, context: NormalizationContext):
        """Override run to handle multiple resource types from one file."""
        from ..core.base import NormalizationSummary
        
        patterns = ["cloudwatch_log_group_*.json"]
        files = self.find_collector_files(context, patterns, subdirs=["events"])
        
        if not files:
            print(f"    ⚠ No CloudWatch data found")
            return NormalizationSummary(
                name=self.name,
                output_path=str(context.output_dir / f"{self.name}.json"),
                record_count=0,
                error_count=0,
            )
        
        all_resources: List[Dict[str, Any]] = []
        errors: List[str] = []
        
        for file_path in files:
            data = self.load_json_file(file_path)
            if not data:
                continue
            
            try:
                # Handle new cloudwatch_log_group structure (from cloudwatch_log_group collector)
                log_group_name = data.get("logGroupName")
                log_group_metadata = data.get("logGroupMetadata", {})
                log_streams = data.get("logStreams", [])
                log_events = data.get("logEvents", [])
                
                if log_group_name:
                    # Normalize log group metadata
                    if log_group_metadata and not log_group_metadata.get("error"):
                        lg = self._normalize_log_group_from_metadata(log_group_name, log_group_metadata, context)
                        if lg:
                            all_resources.append(lg)
                    
                    # Normalize log streams
                    for stream_data in log_streams:
                        stream = self._normalize_log_stream(stream_data, log_group_name, context)
                        if stream:
                            all_resources.append(stream)
                    
                    # Normalize log events
                    for event_data in log_events:
                        event = self._normalize_log_event(event_data, log_group_name, context)
                        if event:
                            all_resources.append(event)
                
                # Also handle old format for backward compatibility
                log_groups = data.get("LogGroups", [])
                for lg_data in log_groups:
                    lg = self._normalize_log_group(lg_data, context)
                    if lg:
                        all_resources.append(lg)
                    
                    # Normalize log streams from this log group
                    old_log_streams = lg_data.get("logStreams", [])
                    old_log_group_name = lg_data.get("logGroupName")
                    for stream_data in old_log_streams:
                        stream = self._normalize_log_stream(stream_data, old_log_group_name, context)
                        if stream:
                            all_resources.append(stream)
                    
                    # Normalize log events from this log group
                    old_log_events = lg_data.get("logEvents", [])
                    for event_data in old_log_events:
                        event = self._normalize_log_event(event_data, old_log_group_name, context)
                        if event:
                            all_resources.append(event)
                
                # Normalize alarms
                alarms = data.get("Alarms", [])
                for alarm_data in alarms:
                    alarm = self._normalize_alarm(alarm_data, context)
                    if alarm:
                        all_resources.append(alarm)
                
                # Normalize EventBridge rules
                events = data.get("Events", [])
                for event_data in events:
                    rule = self._normalize_eventbridge_rule(event_data, context)
                    if rule:
                        all_resources.append(rule)
                
                # Normalize dashboards
                dashboards = data.get("Dashboards", [])
                for dashboard_data in dashboards:
                    dashboard = self._normalize_dashboard(dashboard_data, context)
                    if dashboard:
                        all_resources.append(dashboard)
            
            except Exception as e:
                error_msg = f"Error processing {file_path.name}: {str(e)}"
                errors.append(error_msg)
                print(f"    ⚠ {error_msg}")
        
        # Save normalized resources
        output_path = self.save_normalized(context, all_resources)
        
        print(
            f"    ✓ Normalized {len(all_resources)} resource(s) → {output_path.name} "
            f"({len(errors)} error(s))"
        )
        
        return NormalizationSummary(
            name=self.name,
            output_path=str(output_path),
            record_count=len(all_resources),
            error_count=len(errors),
            errors=errors,
        )
    
    def _normalize_log_group_from_metadata(
        self, log_group_name: str, metadata: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a CloudWatch log group from metadata dict (new format)."""
        log_group_arn = metadata.get("arn")
        account_id = context.account_id
        region = context.region
        
        if log_group_arn:
            parsed_arn = parse_arn(log_group_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="cloudwatch",
            resource_type="log_group",
            resource_identifier=log_group_name,
            account_id=account_id,
            region=region,
        )
        
        # CloudWatch timestamps are in milliseconds
        creation_time_ms = metadata.get("creationTime")
        creation_time = normalize_timestamp(
            creation_time_ms / 1000 if isinstance(creation_time_ms, (int, float)) else creation_time_ms
        )
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.CLOUDWATCH_LOG_GROUP,
            Fields.SERVICE: "cloudwatch",
            Fields.RESOURCE_TYPE: "log_group",
            Fields.RESOURCE_ID: log_group_name,
            Fields.ARN: log_group_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: log_group_name,
            Fields.CREATED_AT: creation_time,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "retention_in_days": metadata.get("retentionInDays"),
            "metric_filter_count": metadata.get("metricFilterCount", 0),
            "stored_bytes": metadata.get("storedBytes", 0),
            "kms_key_id": metadata.get("kmsKeyId"),
        }
        
        return normalized
    
    def _normalize_log_group(
        self, lg_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a CloudWatch log group."""
        log_group_name = lg_data.get("logGroupName")
        if not log_group_name:
            return None
        
        log_group_arn = lg_data.get("arn")
        account_id = context.account_id
        region = context.region
        
        if log_group_arn:
            parsed_arn = parse_arn(log_group_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="cloudwatch",
            resource_type="log_group",
            resource_identifier=log_group_name,
            account_id=account_id,
            region=region,
        )
        
        # CloudWatch timestamps are in milliseconds
        creation_time_ms = lg_data.get("creationTime")
        creation_time = normalize_timestamp(
            creation_time_ms / 1000 if isinstance(creation_time_ms, (int, float)) else creation_time_ms
        )
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.CLOUDWATCH_LOG_GROUP,
            Fields.SERVICE: "cloudwatch",
            Fields.RESOURCE_TYPE: "log_group",
            Fields.RESOURCE_ID: log_group_name,
            Fields.ARN: log_group_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: log_group_name,
            Fields.CREATED_AT: creation_time,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "retention_in_days": lg_data.get("retentionInDays"),
            "stored_bytes": lg_data.get("storedBytes", 0),
            "metric_filter_count": lg_data.get("metricFilterCount", 0),
            "kms_key_id": lg_data.get("kmsKeyId"),
        }
        
        return normalized
    
    def _normalize_log_stream(
        self, stream_data: Dict[str, Any], log_group_name: str, context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a CloudWatch log stream."""
        stream_name = stream_data.get("logStreamName")
        if not stream_name:
            return None
        
        log_group_arn = f"arn:aws:logs:{context.region}:{context.account_id}:log-group:{log_group_name}:*"
        stream_arn = stream_data.get("arn")
        
        account_id = context.account_id
        region = context.region
        
        if stream_arn:
            parsed_arn = parse_arn(stream_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="cloudwatch",
            resource_type="log_stream",
            resource_identifier=f"{log_group_name}/{stream_name}",
            account_id=account_id,
            region=region,
        )
        
        # CloudWatch timestamps are in milliseconds
        creation_time = normalize_timestamp(
            stream_data.get("creationTime") / 1000 if isinstance(stream_data.get("creationTime"), (int, float)) else stream_data.get("creationTime")
        )
        first_event_time = normalize_timestamp(
            stream_data.get("firstEventTimestamp") / 1000 if isinstance(stream_data.get("firstEventTimestamp"), (int, float)) else stream_data.get("firstEventTimestamp")
        )
        last_event_time = normalize_timestamp(
            stream_data.get("lastEventTimestamp") / 1000 if isinstance(stream_data.get("lastEventTimestamp"), (int, float)) else stream_data.get("lastEventTimestamp")
        )
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.CLOUDWATCH_LOG_STREAM,
            Fields.SERVICE: "cloudwatch",
            Fields.RESOURCE_TYPE: "log_stream",
            Fields.RESOURCE_ID: stream_name,
            Fields.ARN: stream_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: stream_name,
            Fields.CREATED_AT: creation_time,
            Fields.FIRST_OBSERVED: first_event_time,
            Fields.LAST_OBSERVED: last_event_time,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "log_group_name": log_group_name,
            "log_group_arn": log_group_arn,
            "stored_bytes": stream_data.get("storedBytes", 0),
            "last_ingestion_time": normalize_timestamp(
                stream_data.get("lastIngestionTime") / 1000 if isinstance(stream_data.get("lastIngestionTime"), (int, float)) else stream_data.get("lastIngestionTime")
            ),
        }
        
        # Add relationship to log group
        log_group_id = generate_resource_id(
            service="cloudwatch",
            resource_type="log_group",
            resource_identifier=log_group_name,
            account_id=account_id,
            region=region,
        )
        normalized[Fields.RELATIONSHIPS] = [
            {
                "target_id": log_group_id,
                "target_type": ResourceTypes.CLOUDWATCH_LOG_GROUP,
                "relationship_type": "contained_in",
            }
        ]
        
        return normalized
    
    def _normalize_log_event(
        self, event_data: Dict[str, Any], log_group_name: str, context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a CloudWatch log event."""
        event_id = event_data.get("eventId")
        message = event_data.get("message", "")
        timestamp = event_data.get("timestamp")
        log_stream_name = event_data.get("logStreamName", "")
        
        if not timestamp:
            return None
        
        # Normalize timestamp (CloudWatch uses milliseconds)
        if isinstance(timestamp, (int, float)):
            # If timestamp is > 1e10, it's likely in milliseconds, convert to seconds
            if timestamp > 1e10:
                event_time = normalize_timestamp(timestamp / 1000)
            else:
                event_time = normalize_timestamp(timestamp)
        else:
            event_time = normalize_timestamp(timestamp)
        
        account_id = context.account_id
        region = context.region
        
        # Try to parse CloudTrail event from message (if it's JSON)
        cloudtrail_event = None
        if message and message.strip().startswith("{"):
            try:
                cloudtrail_event = json.loads(message)
            except (json.JSONDecodeError, ValueError):
                pass
        
        # Generate event ID
        if not event_id:
            event_id = generate_event_id(
                event_name="CloudWatchLogEvent",
                event_time=event_time or "",
                request_id=None,
                account_id=account_id,
            )
        
        resource_id = generate_resource_id(
            service="cloudwatch",
            resource_type="log_event",
            resource_identifier=f"{log_group_name}/{log_stream_name}/{event_id}",
            account_id=account_id,
            region=region,
        )
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.CLOUDWATCH_LOG_EVENT,
            Fields.SERVICE: "cloudwatch",
            Fields.RESOURCE_TYPE: "log_event",
            Fields.EVENT_ID: str(event_id),
            Fields.EVENT_TIME: event_time,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
        }
        
        # Add metadata
        metadata = {
            "log_group_name": log_group_name,
            "log_stream_name": log_stream_name,
            "message": message,
            "ingestion_time": normalize_timestamp(
                event_data.get("ingestionTime") / 1000 if isinstance(event_data.get("ingestionTime"), (int, float)) and event_data.get("ingestionTime", 0) > 1e10 else event_data.get("ingestionTime")
            ),
        }
        
        # If this is a CloudTrail event, extract key fields
        if cloudtrail_event:
            metadata["is_cloudtrail_event"] = True
            metadata["cloudtrail_event_name"] = cloudtrail_event.get("eventName")
            metadata["cloudtrail_event_source"] = cloudtrail_event.get("eventSource")
            metadata["cloudtrail_event_type"] = cloudtrail_event.get("eventType")
            metadata["cloudtrail_user_identity"] = cloudtrail_event.get("userIdentity", {})
            metadata["cloudtrail_source_ip"] = cloudtrail_event.get("sourceIPAddress")
            metadata["cloudtrail_user_agent"] = cloudtrail_event.get("userAgent")
            metadata["cloudtrail_request_id"] = cloudtrail_event.get("requestID")
            metadata["cloudtrail_error_code"] = cloudtrail_event.get("errorCode")
            metadata["cloudtrail_error_message"] = cloudtrail_event.get("errorMessage")
            
            # Add CloudTrail-specific fields to top level for easier querying
            normalized[Fields.EVENT_NAME] = cloudtrail_event.get("eventName")
            normalized[Fields.EVENT_SOURCE] = cloudtrail_event.get("eventSource")
            normalized[Fields.EVENT_TYPE] = cloudtrail_event.get("eventType")
            normalized[Fields.USER_IDENTITY] = cloudtrail_event.get("userIdentity", {})
            normalized[Fields.SOURCE_IP] = cloudtrail_event.get("sourceIPAddress")
            normalized[Fields.USER_AGENT] = cloudtrail_event.get("userAgent")
            normalized[Fields.REQUEST_ID] = cloudtrail_event.get("requestID")
            normalized[Fields.ERROR_CODE] = cloudtrail_event.get("errorCode")
            normalized[Fields.ERROR_MESSAGE] = cloudtrail_event.get("errorMessage")
        else:
            metadata["is_cloudtrail_event"] = False
        
        normalized[Fields.METADATA] = metadata
        
        # Add relationships
        relationships = []
        
        # Relationship to log group
        log_group_id = generate_resource_id(
            service="cloudwatch",
            resource_type="log_group",
            resource_identifier=log_group_name,
            account_id=account_id,
            region=region,
        )
        relationships.append({
            "target_id": log_group_id,
            "target_type": ResourceTypes.CLOUDWATCH_LOG_GROUP,
            "relationship_type": "contained_in",
        })
        
        # Relationship to log stream
        if log_stream_name:
            stream_id = generate_resource_id(
                service="cloudwatch",
                resource_type="log_stream",
                resource_identifier=f"{log_group_name}/{log_stream_name}",
                account_id=account_id,
                region=region,
            )
            relationships.append({
                "target_id": stream_id,
                "target_type": ResourceTypes.CLOUDWATCH_LOG_STREAM,
                "relationship_type": "contained_in",
            })
        
        if relationships:
            normalized[Fields.RELATIONSHIPS] = relationships
        
        return normalized
    
    def _normalize_eventbridge_rule(
        self, rule_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize an EventBridge rule."""
        rule_name = rule_data.get("Name")
        if not rule_name:
            return None
        
        rule_arn = rule_data.get("Arn")
        account_id = context.account_id
        region = context.region
        
        if rule_arn:
            parsed_arn = parse_arn(rule_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="eventbridge",
            resource_type="rule",
            resource_identifier=rule_name,
            account_id=account_id,
            region=region,
        )
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.EVENTBRIDGE_RULE,
            Fields.SERVICE: "eventbridge",
            Fields.RESOURCE_TYPE: "rule",
            Fields.RESOURCE_ID: rule_name,
            Fields.ARN: rule_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: rule_name,
            Fields.STATE: rule_data.get("State", "").lower(),
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "description": rule_data.get("Description"),
            "schedule_expression": rule_data.get("ScheduleExpression"),
            "event_pattern": rule_data.get("EventPattern"),
            "event_bus_name": rule_data.get("EventBusName"),
            "targets": rule_data.get("Targets", []),
            "created_by": rule_data.get("CreatedBy"),
            "managed_by": rule_data.get("ManagedBy"),
        }
        
        return normalized
    
    def _normalize_dashboard(
        self, dashboard_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a CloudWatch dashboard."""
        dashboard_name = dashboard_data.get("DashboardName")
        if not dashboard_name:
            return None
        
        dashboard_arn = dashboard_data.get("DashboardArn")
        account_id = context.account_id
        region = context.region
        
        if dashboard_arn:
            parsed_arn = parse_arn(dashboard_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="cloudwatch",
            resource_type="dashboard",
            resource_identifier=dashboard_name,
            account_id=account_id,
            region=region,
        )
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: "aws.cloudwatch.dashboard",
            Fields.SERVICE: "cloudwatch",
            Fields.RESOURCE_TYPE: "dashboard",
            Fields.RESOURCE_ID: dashboard_name,
            Fields.ARN: dashboard_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: dashboard_name,
            Fields.LAST_MODIFIED: normalize_timestamp(dashboard_data.get("LastModified")),
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "size": dashboard_data.get("Size", 0),
            "dashboard_body": dashboard_data.get("DashboardBody"),
        }
        
        return normalized
    
    def _normalize_alarm(
        self, alarm_data: Dict[str, Any], context: NormalizationContext
    ) -> Optional[Dict[str, Any]]:
        """Normalize a CloudWatch alarm."""
        alarm_name = alarm_data.get("AlarmName")
        if not alarm_name:
            return None
        
        alarm_arn = alarm_data.get("AlarmArn")
        account_id = context.account_id
        region = context.region
        
        if alarm_arn:
            parsed_arn = parse_arn(alarm_arn)
            if parsed_arn:
                account_id = parsed_arn.get("account_id") or account_id
                region = parsed_arn.get("region") or region
        
        resource_id = generate_resource_id(
            service="cloudwatch",
            resource_type="alarm",
            resource_identifier=alarm_name,
            account_id=account_id,
            region=region,
        )
        
        state = alarm_data.get("StateValue", "").lower()
        
        normalized = {
            Fields.ID: resource_id,
            Fields.TYPE: ResourceTypes.CLOUDWATCH_ALARM,
            Fields.SERVICE: "cloudwatch",
            Fields.RESOURCE_TYPE: "alarm",
            Fields.RESOURCE_ID: alarm_name,
            Fields.ARN: alarm_arn,
            Fields.ACCOUNT_ID: account_id,
            Fields.REGION: region,
            Fields.NAME: alarm_name,
            Fields.STATE: state,
            Fields.STATUS: state,
        }
        
        # Add metadata
        normalized[Fields.METADATA] = {
            "alarm_description": alarm_data.get("AlarmDescription"),
            "metric_name": alarm_data.get("MetricName"),
            "namespace": alarm_data.get("Namespace"),
            "state_reason": alarm_data.get("StateReason"),
            "state_updated_timestamp": normalize_timestamp(alarm_data.get("StateUpdatedTimestamp")),
            "comparison_operator": alarm_data.get("ComparisonOperator"),
            "threshold": alarm_data.get("Threshold"),
            "evaluation_periods": alarm_data.get("EvaluationPeriods"),
            "period": alarm_data.get("Period"),
        }
        
        return normalized

