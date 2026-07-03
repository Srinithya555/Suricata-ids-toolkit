import sys, os, struct, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcap_toolkit.packet_builder import (
    build_tcp_packet, build_udp_packet, build_dns_query, build_http_get,
    TCP_FLAG_SYN, TCP_FLAG_ACK, ip_checksum,
)
from pcap_toolkit.pcap_writer import write_pcap
from pcap_toolkit.pcap_reader import parse_pcap, parse_dns_query_name, read_pcap_records

MAC_A, MAC_B = "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"


class TestChecksums:
    def test_ip_header_checksum_self_verifies(self):
        """A correctly-checksummed IPv4 header's 16-bit words (including
        its own checksum field) must sum to exactly 0xFFFF."""
        packet = build_tcp_packet(MAC_A, MAC_B, "10.0.0.1", "10.0.0.2", 1234, 80, 0, 0, TCP_FLAG_SYN)
        ip_header = packet[14:34]
        total = sum(struct.unpack("!10H", ip_header))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        assert total == 0xFFFF

    def test_checksum_changes_if_data_corrupted(self):
        """Sanity check that the checksum function actually detects
        corruption, rather than trivially always validating."""
        data = b"\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"
        original = ip_checksum(data)
        corrupted = bytearray(data)
        corrupted[5] ^= 0xFF  # flip a byte
        corrupted_checksum = ip_checksum(bytes(corrupted))
        assert original != corrupted_checksum


class TestPcapRoundTrip:
    def test_tcp_packet_survives_round_trip(self):
        packet = build_tcp_packet(MAC_A, MAC_B, "10.0.0.5", "93.184.216.34", 45123, 80, 1000, 0, TCP_FLAG_SYN)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            write_pcap(tmp.name, [packet])
            parsed = parse_pcap(tmp.name)
        os.unlink(tmp.name)

        assert len(parsed) == 1
        assert parsed[0].src_ip == "10.0.0.5"
        assert parsed[0].dst_ip == "93.184.216.34"
        assert parsed[0].src_port == 45123
        assert parsed[0].dst_port == 80
        assert parsed[0].protocol == "TCP"
        assert parsed[0].tcp_flags & TCP_FLAG_SYN

    def test_http_payload_survives_round_trip_byte_for_byte(self):
        payload = build_http_get("example.com", "/search?q=test", "TestAgent/1.0")
        packet = build_tcp_packet(MAC_A, MAC_B, "10.0.0.5", "10.0.0.10", 1111, 80, 0, 1, TCP_FLAG_ACK, payload)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            write_pcap(tmp.name, [packet])
            parsed = parse_pcap(tmp.name)
        os.unlink(tmp.name)
        assert parsed[0].payload == payload

    def test_dns_query_name_survives_round_trip(self):
        payload = build_dns_query("www.example.com")
        packet = build_udp_packet(MAC_A, MAC_B, "10.0.0.5", "8.8.8.8", 5000, 53, payload)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            write_pcap(tmp.name, [packet])
            parsed = parse_pcap(tmp.name)
        os.unlink(tmp.name)
        assert parse_dns_query_name(parsed[0].payload) == "www.example.com"

    def test_multiple_packets_preserve_order(self):
        packets = [
            build_tcp_packet(MAC_A, MAC_B, "10.0.0.1", "10.0.0.2", 1000 + i, 80, i, 0, TCP_FLAG_SYN)
            for i in range(5)
        ]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            write_pcap(tmp.name, packets)
            parsed = parse_pcap(tmp.name)
        os.unlink(tmp.name)
        assert [p.src_port for p in parsed] == [1000, 1001, 1002, 1003, 1004]

    def test_explicit_timestamps_are_preserved(self):
        packets = [build_tcp_packet(MAC_A, MAC_B, "10.0.0.1", "10.0.0.2", 1000, 80, 0, 0, TCP_FLAG_SYN) for _ in range(3)]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            write_pcap(tmp.name, packets, timestamps=[0, 5, 100])
            records = read_pcap_records(tmp.name)
        os.unlink(tmp.name)
        offsets = [ts - records[0][0] for ts, _ in records]
        assert offsets == [0, 5, 100]

    def test_rejects_invalid_magic_number(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(b"NOTAPCAP" + b"\x00" * 16)
            tmp.flush()
            try:
                parse_pcap(tmp.name)
                assert False, "expected ValueError for bad magic number"
            except ValueError:
                pass
        os.unlink(tmp.name)
