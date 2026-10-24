"""AWS Lambda handler for API Gateway HTTP API (proxy integration)."""
import json
from detector import analyze_url

def lambda_handler(event, context):
    method = (
        event.get("requestContext", {}).get("http", {}).get("method")
        or event.get("httpMethod", "GET")
    )
    path = event.get("rawPath") or event.get("path") or "/"
    headers = {
        "content-type": "application/json",
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "content-type",
        "access-control-allow-methods": "GET,POST,OPTIONS",
    }
    if method == "OPTIONS":
        return {"statusCode": 204, "headers": headers, "body": ""}
    if path.endswith("/health"):
        return {"statusCode": 200, "headers": headers, "body": json.dumps({"status":"ok"})}
    if method != "POST":
        return {"statusCode": 405, "headers": headers, "body": json.dumps({"error":"Use POST with JSON {\"url\":\"https://example.com\"}."})}
    try:
        body = event.get("body") or "{}"
        if event.get("isBase64Encoded"):
            import base64
            body = base64.b64decode(body).decode("utf-8")
        payload = json.loads(body)
        url = (payload.get("url") or "").strip()
        if not url:
            raise ValueError("Please enter a URL to check.")
        result = analyze_url(url)
        return {"statusCode": 200, "headers": headers, "body": json.dumps(result)}
    except ValueError as exc:
        return {"statusCode": 400, "headers": headers, "body": json.dumps({"error": str(exc)})}
    except Exception:
        return {"statusCode": 500, "headers": headers, "body": json.dumps({"error":"Internal server error"})}
