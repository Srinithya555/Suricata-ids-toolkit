"""
Generates real, byte-accurate PCAP files covering each detection pattern
in this toolkit, plus a benign-traffic pcap for false-positive testing.

Run: python fixtures/generate_pcaps.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcap_toolkit.packet_builder import (
    build_tcp_packet, build_udp_packet, build_dns_query, build_http_get,
    TCP_FLAG_SYN, TCP_FLAG_ACK,
)
from pcap_toolkit.pcap_writer import write_pcap

FIXTURES_DIR = os.path.dirname(os.path.abspath(__file__))
ATTACKER_IP = "198.51.100.66"
VICTIM_IP = "10.0.0.10"
SRC_MAC, DST_MAC = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"


def make_sqli_pcap():
    payload = build_http_get(VICTIM_IP, "/login?user=admin' OR '1'='1", "sqlmap/1.6")
    packet = build_tcp_packet(SRC_MAC, DST_MAC, ATTACKER_IP, VICTIM_IP, 51234, 80, 1000, 1, TCP_FLAG_ACK, payload)
    write_pcap(os.path.join(FIXTURES_DIR, "sqli_attack.pcap"), [packet])


def make_benign_http_pcap():
    payload = build_http_get(VICTIM_IP, "/products?category=shoes", "Mozilla/5.0 (Windows NT 10.0)")
    packet = build_tcp_packet(SRC_MAC, DST_MAC, "203.0.113.20", VICTIM_IP, 51235, 80, 1000, 1, TCP_FLAG_ACK, payload)
    write_pcap(os.path.join(FIXTURES_DIR, "benign_http.pcap"), [packet])


def make_dns_tunneling_pcap():
    long_label = "aGVsbG93b3JsZHRoaXNpc2Fsb25nc3ViZG9tYWlubGFiZWw"  # > 40 chars, base64-ish
    query_payload = build_dns_query(f"{long_label}.evil-c2.example")
    packet = build_udp_packet(SRC_MAC, DST_MAC, VICTIM_IP, "8.8.8.8", 53421, 53, query_payload)
    write_pcap(os.path.join(FIXTURES_DIR, "dns_tunneling.pcap"), [packet])


def make_benign_dns_pcap():
    query_payload = build_dns_query("www.example.com")
    packet = build_udp_packet(SRC_MAC, DST_MAC, VICTIM_IP, "8.8.8.8", 53422, 53, query_payload)
    write_pcap(os.path.join(FIXTURES_DIR, "benign_dns.pcap"), [packet])


def make_port_scan_pcap():
    """6 SYN packets from one attacker to 6 distinct ports, all within
    a 5-second span — should trigger the port scan detector (threshold 5)."""
    packets, timestamps = [], []
    for i, port in enumerate([22, 80, 443, 3389, 8080, 8443]):
        pkt = build_tcp_packet(SRC_MAC, DST_MAC, ATTACKER_IP, VICTIM_IP, 40000 + i, port, 1000 + i, 0, TCP_FLAG_SYN)
        packets.append(pkt)
        timestamps.append(i)  # 0,1,2,3,4,5 seconds — all within a 10s window
    write_pcap(os.path.join(FIXTURES_DIR, "port_scan.pcap"), packets, timestamps)


def make_benign_tcp_pcap():
    """A normal client repeatedly hitting the SAME port (443) — should
    NOT trigger the port scan detector, since distinct ports stays at 1."""
    packets, timestamps = [], []
    for i in range(6):
        pkt = build_tcp_packet(SRC_MAC, DST_MAC, "203.0.113.20", VICTIM_IP, 50000 + i, 443, 1000 + i, 0, TCP_FLAG_SYN)
        packets.append(pkt)
        timestamps.append(i)
    write_pcap(os.path.join(FIXTURES_DIR, "benign_repeated_connections.pcap"), packets, timestamps)


def main():
    make_sqli_pcap()
    make_benign_http_pcap()
    make_dns_tunneling_pcap()
    make_benign_dns_pcap()
    make_port_scan_pcap()
    make_benign_tcp_pcap()
    print("Generated 6 pcap fixtures in", FIXTURES_DIR)


if __name__ == "__main__":
    main()
