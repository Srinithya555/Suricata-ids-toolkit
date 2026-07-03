"""
Reimplements, in testable Python, the same matching logic as the Suricata
rules in suricata-rules/sql_injection_http.rules — content matches
against the HTTP request line/headers extracted from a TCP payload. This
is NOT a general HTTP parser; it extracts just enough (request line,
Host header, User-Agent header) to test the same signatures the real
Suricata rules encode.
"""
import re
from dataclasses import dataclass


@dataclass
class HttpAlert:
    sid: int
    msg: str
    mitre_technique: str


HTTP_RULES = [
    {"sid": 1000001, "msg": "SQLI - Common SQL injection pattern in URI",
     "field": "uri", "pattern": re.compile(r"' OR '", re.IGNORECASE), "mitre": "T1190"},
    {"sid": 1000002, "msg": "SQLI - UNION SELECT pattern in URI",
     "field": "uri", "pattern": re.compile(r"UNION SELECT", re.IGNORECASE), "mitre": "T1190"},
    {"sid": 1000003, "msg": "SQLI - Known SQLMap user agent",
     "field": "user_agent", "pattern": re.compile(r"sqlmap", re.IGNORECASE), "mitre": "T1190"},
]


def parse_http_request(payload: bytes) -> dict:
    """Extracts uri, host, and user_agent from a raw HTTP request payload."""
    try:
        text = payload.decode(errors="replace")
    except Exception:
        return {}
    lines = text.split("\r\n")
    if not lines or " HTTP/" not in lines[0]:
        return {}

    request_line = lines[0]
    # A naive `request_line.split(" ")` breaks when the URI itself
    # contains an unencoded literal space — which real attack payloads
    # sometimes do (e.g. "admin' OR '1'='1" has spaces around OR).
    # Anchor on the method prefix and the "HTTP/x.x" suffix instead, so
    # everything in between — spaces and all — is captured as the URI.
    match = re.match(r"^(\S+)\s+(.*)\s+(HTTP/\d\.\d)$", request_line)
    if not match:
        return {}
    _, uri, _ = match.groups()

    headers = {}
    for line in lines[1:]:
        if ": " in line:
            key, _, value = line.partition(": ")
            headers[key.lower()] = value

    return {"uri": uri, "host": headers.get("host", ""), "user_agent": headers.get("user-agent", "")}


def evaluate_http_rules(http_fields: dict) -> list:
    alerts = []
    for rule in HTTP_RULES:
        value = http_fields.get(rule["field"], "")
        if value and rule["pattern"].search(value):
            alerts.append(HttpAlert(sid=rule["sid"], msg=rule["msg"], mitre_technique=rule["mitre"]))
    return alerts
