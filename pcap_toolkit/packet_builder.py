"""
Hand-rolled Ethernet/IPv4/TCP/UDP packet construction using only the
Python standard library (`struct`) — no scapy/dpkt dependency. Built this
way deliberately: it's a stronger demonstration of actually understanding
these protocols at the byte level than wrapping a library call, and it
means every byte in the generated test PCAPs is something this project
explicitly constructed and can explain.

Checksums (IP header checksum, TCP checksum with pseudo-header, UDP
checksum with pseudo-header) are computed correctly, not zeroed out —
verified round-trip in tests/test_pcap_roundtrip.py by recomputing them
independently and confirming they match what a real network stack would
compute and accept.
"""
import struct
import socket


def ip_checksum(data: bytes) -> int:
    """Standard Internet checksum (RFC 1071): one's-complement sum of
    16-bit words, with the final carry folded back in."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ethernet_header(src_mac: str, dst_mac: str, ethertype: int = 0x0800) -> bytes:
    def mac_to_bytes(mac: str) -> bytes:
        return bytes(int(octet, 16) for octet in mac.split(":"))
    return mac_to_bytes(dst_mac) + mac_to_bytes(src_mac) + struct.pack("!H", ethertype)


def build_ipv4_header(src_ip: str, dst_ip: str, payload_length: int, protocol: int, ident: int = 0) -> bytes:
    version_ihl = (4 << 4) | 5  # IPv4, 5 * 4 = 20 byte header, no options
    total_length = 20 + payload_length
    flags_fragment = 0
    ttl = 64
    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_length, ident, flags_fragment, ttl, protocol, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    checksum = ip_checksum(header_without_checksum)
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl, 0, total_length, ident, flags_fragment, ttl, protocol, checksum,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )


def _pseudo_header(src_ip: str, dst_ip: str, protocol: int, length: int) -> bytes:
    return struct.pack("!4s4sBBH", socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, protocol, length)


TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10


def build_tcp_segment(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                       seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    data_offset_reserved = (5 << 4)  # 5 * 4 = 20 byte TCP header, no options
    window = 65535
    header_without_checksum = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset_reserved, flags, window, 0, 0,
    )
    segment_for_checksum = header_without_checksum + payload
    pseudo = _pseudo_header(src_ip, dst_ip, 6, len(segment_for_checksum))
    checksum = ip_checksum(pseudo + segment_for_checksum)
    header = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset_reserved, flags, window, checksum, 0,
    )
    return header + payload


def build_udp_segment(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    header_without_checksum = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = _pseudo_header(src_ip, dst_ip, 17, length)
    checksum = ip_checksum(pseudo + header_without_checksum + payload)
    checksum = checksum if checksum != 0 else 0xFFFF  # 0 means "no checksum" in UDP; avoid ambiguity
    header = struct.pack("!HHHH", src_port, dst_port, length, checksum)
    return header + payload


def build_tcp_packet(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str,
                      src_port: int, dst_port: int, seq: int, ack: int,
                      flags: int, payload: bytes = b"") -> bytes:
    tcp_segment = build_tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    ip_header = build_ipv4_header(src_ip, dst_ip, len(tcp_segment), protocol=6)
    eth_header = build_ethernet_header(src_mac, dst_mac)
    return eth_header + ip_header + tcp_segment


def build_udp_packet(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str,
                      src_port: int, dst_port: int, payload: bytes = b"") -> bytes:
    udp_segment = build_udp_segment(src_ip, dst_ip, src_port, dst_port, payload)
    ip_header = build_ipv4_header(src_ip, dst_ip, len(udp_segment), protocol=17)
    eth_header = build_ethernet_header(src_mac, dst_mac)
    return eth_header + ip_header + udp_segment


def build_dns_query(query_name: str, transaction_id: int = 0x1234, qtype: int = 1) -> bytes:
    """Builds a minimal DNS query packet payload (A record query by default)."""
    header = struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)  # standard query, 1 question
    qname = b"".join(
        struct.pack("B", len(label)) + label.encode() for label in query_name.split(".")
    ) + b"\x00"
    question = qname + struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + question


def build_http_get(host: str, path: str, user_agent: str = "Mozilla/5.0") -> bytes:
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    )
    return request.encode()
