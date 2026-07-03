"""
Reimplements, in testable Python, the same matching logic as
suricata-rules/dns_tunneling.rules: flags DNS queries with an unusually
long subdomain label (a common tunneling indicator, since tunneling
tools encode data into query names) and queries to a known-suspicious
domain suffix.
"""
import re
from dataclasses import dataclass

LONG_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9+/=]{40,}\.")
SUSPICIOUS_SUFFIX = ".evil-c2."


@dataclass
class DnsAlert:
    sid: int
    msg: str
    mitre_technique: str


def evaluate_dns_rules(query_name: str) -> list:
    alerts = []
    if LONG_LABEL_PATTERN.match(query_name):
        alerts.append(DnsAlert(
            sid=1000010, msg="DNS - Possible tunneling via long subdomain label",
            mitre_technique="T1071.004",
        ))
    if SUSPICIOUS_SUFFIX in f".{query_name}.":
        alerts.append(DnsAlert(
            sid=1000011, msg="DNS - Query to known suspicious TLD pattern",
            mitre_technique="T1071.004",
        ))
    return alerts
