"""
Reimplements, in testable Python, the same detection logic as
suricata-rules/port_scan_detection.rules: flags a source IP that sends
TCP SYN packets to N or more DISTINCT destination ports within a sliding
time window — the classic signature of a port scan, as opposed to normal
traffic where one source usually talks to a small number of ports
repeatedly.
"""
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class PortScanAlert:
    sid: int
    msg: str
    src_ip: str
    distinct_ports_hit: int
    mitre_technique: str


TCP_FLAG_SYN = 0x02


def detect_port_scans(packets: list, port_threshold: int = 5, window_seconds: int = 10) -> list:
    """
    packets: list of ParsedPacket (must have .timestamp set — packets
    without a timestamp are skipped, since the window logic is
    meaningless without one).

    Algorithm: for each source IP, maintain a sliding window of
    (timestamp, dst_port) for SYN packets. On each new SYN, drop entries
    older than window_seconds, then check if the number of DISTINCT ports
    in the remaining window meets the threshold. Alerts at most once per
    source IP (the first time the threshold is crossed), matching
    Suricata's detection_filter semantics of alerting once the count
    condition is met rather than on every subsequent packet.
    """
    windows = defaultdict(list)  # src_ip -> list of (timestamp, port)
    alerted_sources = set()
    alerts = []

    for pkt in packets:
        if pkt.protocol != "TCP" or pkt.tcp_flags is None:
            continue
        if not (pkt.tcp_flags & TCP_FLAG_SYN):
            continue
        if pkt.timestamp is None:
            continue

        window = windows[pkt.src_ip]
        window.append((pkt.timestamp, pkt.dst_port))
        # Drop entries outside the sliding window relative to this packet's time
        cutoff = pkt.timestamp - window_seconds
        windows[pkt.src_ip] = [(t, p) for t, p in window if t >= cutoff]

        distinct_ports = {p for _, p in windows[pkt.src_ip]}
        if len(distinct_ports) >= port_threshold and pkt.src_ip not in alerted_sources:
            alerted_sources.add(pkt.src_ip)
            alerts.append(PortScanAlert(
                sid=1000020, msg="SCAN - Possible TCP port scan (multiple SYN, distinct ports)",
                src_ip=pkt.src_ip, distinct_ports_hit=len(distinct_ports), mitre_technique="T1046",
            ))

    return alerts
