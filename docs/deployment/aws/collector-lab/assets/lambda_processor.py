import json


def handler(event, context):
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(
            {
                "service": "ventra-lab-api",
                "story": "admin-endpoint",
                "event": event.get("path", "/"),
            }
        ),
    }
