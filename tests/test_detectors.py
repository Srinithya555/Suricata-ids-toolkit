import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.http_rule_engine import parse_http_request, evaluate_http_rules
from detection.dns_tunneling_detector import evaluate_dns_rules
from detection.port_scan_detector import detect_port_scans
from pcap_toolkit.pcap_reader import ParsedPacket
from pcap_toolkit.packet_builder import build_http_get


class TestHttpRuleEngine:
    def test_parses_uri_with_literal_space_correctly(self):
        """Regression test for a real bug: naive space-splitting the
        request line truncates a URI containing an unencoded space."""
        payload = build_http_get("10.0.0.10", "/login?user=admin' OR '1'='1", "sqlmap/1.6")
        fields = parse_http_request(payload)
        assert fields["uri"] == "/login?user=admin' OR '1'='1"

    def test_detects_or_injection_pattern(self):
        alerts = evaluate_http_rules({"uri": "/x?a=1' OR '1'='1", "user_agent": "Mozilla"})
        assert any(a.sid == 1000001 for a in alerts)

    def test_detects_union_select_pattern(self):
        alerts = evaluate_http_rules({"uri": "/x?id=1 UNION SELECT password FROM users", "user_agent": "Mozilla"})
        assert any(a.sid == 1000002 for a in alerts)

    def test_detects_sqlmap_user_agent(self):
        alerts = evaluate_http_rules({"uri": "/", "user_agent": "sqlmap/1.6.12"})
        assert any(a.sid == 1000003 for a in alerts)

    def test_benign_request_triggers_nothing(self):
        alerts = evaluate_http_rules({"uri": "/products?category=shoes", "user_agent": "Mozilla/5.0"})
        assert alerts == []

    def test_non_http_payload_returns_empty_fields(self):
        assert parse_http_request(b"\x01\x02\x03random binary garbage") == {}


class TestDnsTunnelingDetector:
    def test_long_label_flagged(self):
        alerts = evaluate_dns_rules("aGVsbG93b3JsZHRoaXNpc2Fsb25nc3ViZG9tYWlubGFiZWw.example.com")
        assert any(a.sid == 1000010 for a in alerts)

    def test_short_label_not_flagged(self):
        alerts = evaluate_dns_rules("www.example.com")
        assert alerts == []

    def test_suspicious_suffix_flagged(self):
        alerts = evaluate_dns_rules("short.evil-c2.example")
        assert any(a.sid == 1000011 for a in alerts)

    def test_both_rules_can_fire_together(self):
        long_label = "a" * 45
        alerts = evaluate_dns_rules(f"{long_label}.evil-c2.example")
        sids = {a.sid for a in alerts}
        assert sids == {1000010, 1000011}


class TestPortScanDetector:
    def _syn_packet(self, src_ip, dst_port, timestamp):
        return ParsedPacket(src_ip=src_ip, dst_ip="10.0.0.10", protocol="TCP",
                             src_port=40000, dst_port=dst_port, tcp_flags=0x02, timestamp=timestamp)

    def test_flags_scan_across_distinct_ports_within_window(self):
        packets = [self._syn_packet("198.51.100.1", port, i) for i, port in enumerate([22, 80, 443, 3389, 8080])]
        alerts = detect_port_scans(packets, port_threshold=5, window_seconds=10)
        assert len(alerts) == 1
        assert alerts[0].src_ip == "198.51.100.1"

    def test_does_not_flag_repeated_connections_to_same_port(self):
        packets = [self._syn_packet("203.0.113.1", 443, i) for i in range(10)]
        alerts = detect_port_scans(packets, port_threshold=5, window_seconds=10)
        assert alerts == []

    def test_does_not_flag_below_threshold(self):
        packets = [self._syn_packet("198.51.100.1", port, i) for i, port in enumerate([22, 80, 443])]
        alerts = detect_port_scans(packets, port_threshold=5, window_seconds=10)
        assert alerts == []

    def test_ports_outside_time_window_do_not_count_together(self):
        """5 distinct ports, but spread across 100 seconds — should NOT
        trigger a 10-second-window scan detection, since no 10-second
        slice contains 5 distinct ports."""
        packets = [self._syn_packet("198.51.100.1", port, i * 20) for i, port in enumerate([22, 80, 443, 3389, 8080])]
        alerts = detect_port_scans(packets, port_threshold=5, window_seconds=10)
        assert alerts == []

    def test_alerts_once_per_source_not_once_per_packet(self):
        """Once the threshold is crossed, additional SYNs from the same
        source shouldn't generate additional alerts (matches Suricata's
        detection_filter semantics)."""
        packets = [self._syn_packet("198.51.100.1", port, i) for i, port in enumerate([22, 80, 443, 3389, 8080, 8443, 9000])]
        alerts = detect_port_scans(packets, port_threshold=5, window_seconds=10)
        assert len(alerts) == 1

    def test_multiple_sources_scanning_both_get_flagged(self):
        packets = (
            [self._syn_packet("198.51.100.1", port, i) for i, port in enumerate([22, 80, 443, 3389, 8080])]
            + [self._syn_packet("198.51.100.2", port, i) for i, port in enumerate([21, 23, 25, 110, 143])]
        )
        alerts = detect_port_scans(packets, port_threshold=5, window_seconds=10)
        assert {a.src_ip for a in alerts} == {"198.51.100.1", "198.51.100.2"}

    def test_non_syn_packets_ignored(self):
        packets = [
            ParsedPacket(src_ip="198.51.100.1", dst_ip="10.0.0.10", protocol="TCP",
                         dst_port=port, tcp_flags=0x10, timestamp=i)  # ACK only, not SYN
            for i, port in enumerate([22, 80, 443, 3389, 8080])
        ]
        alerts = detect_port_scans(packets, port_threshold=5, window_seconds=10)
        assert alerts == []

    def test_packets_without_timestamp_are_skipped_not_crashed(self):
        packets = [self._syn_packet("198.51.100.1", 22, None)]
        alerts = detect_port_scans(packets)
        assert alerts == []
