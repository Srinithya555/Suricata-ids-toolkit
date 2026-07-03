#!/usr/bin/env python3
"""
Usage: python scripts/analyze_pcap.py fixtures/sqli_attack.pcap
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcap_toolkit.pcap_reader import parse_pcap, parse_dns_query_name
from detection.http_rule_engine import parse_http_request, evaluate_http_rules
from detection.dns_tunneling_detector import evaluate_dns_rules
from detection.port_scan_detector import detect_port_scans


def analyze(pcap_path: str) -> list:
    packets = parse_pcap(pcap_path)
    alerts = []

    for pkt in packets:
        if pkt.protocol == "TCP" and pkt.payload:
            http_fields = parse_http_request(pkt.payload)
            if http_fields:
                for a in evaluate_http_rules(http_fields):
                    alerts.append(f"[SID {a.sid}] {a.msg} (MITRE {a.mitre_technique}) — {pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port}")

        if pkt.protocol == "UDP" and pkt.dst_port == 53:
            query_name = parse_dns_query_name(pkt.payload)
            for a in evaluate_dns_rules(query_name):
                alerts.append(f"[SID {a.sid}] {a.msg} (MITRE {a.mitre_technique}) — query: {query_name}")

    for a in detect_port_scans(packets):
        alerts.append(f"[SID {a.sid}] {a.msg} (MITRE {a.mitre_technique}) — {a.src_ip} hit {a.distinct_ports_hit} distinct ports")

    return alerts


def main():
    parser = argparse.ArgumentParser(description="Analyze a pcap file for IDS-detectable attack patterns.")
    parser.add_argument("pcap_file")
    args = parser.parse_args()

    alerts = analyze(args.pcap_file)
    if not alerts:
        print("No alerts.")
    for a in alerts:
        print(a)

    sys.exit(1 if alerts else 0)


if __name__ == "__main__":
    main()
