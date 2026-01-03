"""
Correlation schema definitions.

Defines fields and structures used for correlation data.
"""


class CorrelationFields:
    """Standardized field names for correlation data."""
    
    # Correlation metadata
    CORRELATIONS = "correlations"
    
    # Related items
    RELATED_EVENTS = "related_events"
    RELATED_RESOURCES = "related_resources"
    RELATED_FINDINGS = "related_findings"
    
    # Relationship details
    RELATIONSHIP_TYPE = "relationship_type"
    RELATIONSHIP_CONFIDENCE = "confidence"
    RELATIONSHIP_EVIDENCE = "evidence"
    TIME_DIFF_SECONDS = "time_diff_seconds"
    
    # Timeline data
    TIMELINE = "timeline"
    FIRST_SEEN = "first_seen"
    LAST_SEEN = "last_seen"
    TOTAL_EVENTS = "total_events"
    UNIQUE_IPS = "unique_ips"
    UNIQUE_REGIONS = "unique_regions"
    UNIQUE_SERVICES = "unique_services"
    
    # Pattern detection
    PATTERNS = "patterns"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RECONNAISSANCE = "reconnaissance"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    GEOGRAPHIC_ANOMALY = "geographic_anomaly"
    SUSTAINED_ACTIVITY = "sustained_activity"
    
    # Attack chain
    ATTACK_CHAIN = "attack_chain"
    
    # User activity
    USER_ACTIVITY = "user_activity"
    
    # IP activity
    IP_ACTIVITY = "ip_activity"


class RelationshipTypes:
    """Types of relationships between records."""
    
    # Event relationships
    SAME_USER = "same_user"
    SAME_IP = "same_ip"
    SAME_ACCESS_KEY = "same_access_key"
    SAME_SESSION = "same_session"
    TEMPORAL_PROXIMITY = "temporal_proximity"
    RELATED_API_CALLS = "related_api_calls"
    
    # Event-to-resource relationships
    AFFECTS_RESOURCE = "affects_resource"
    CREATED_RESOURCE = "created_resource"
    MODIFIED_RESOURCE = "modified_resource"
    DELETED_RESOURCE = "deleted_resource"
    ACCESSED_RESOURCE = "accessed_resource"
    TRIGGERED_BY = "triggered_by"
    
    # Resource relationships
    CONTAINS = "contains"
    USES = "uses"
    ATTACHED_TO = "attached_to"
    DEPENDS_ON = "depends_on"
    MEMBER_OF = "member_of"

