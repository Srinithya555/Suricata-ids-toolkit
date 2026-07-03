"""
Reads a libpcap file and parses each Ethernet/IPv4/TCP-or-UDP frame into a
normalized dict — same "normalize once, let rules work on plain dicts"
philosophy used throughout this portfolio (rules never touch raw bytes,
only the parsed dict from here).
"""
import struct
import socket
from dataclasses import dataclass, field


@dataclass
class ParsedPacket:
    src_ip: str
    dst_ip: str
    protocol: str  # "TCP" | "UDP" | "OTHER"
    src_port: int = None
    dst_port: int = None
    tcp_flags: int = None
    payload: bytes = b""
    timestamp: int = None


def read_pcap_records(path: str) -> list:
    """Returns a list of (timestamp_seconds, raw_frame_bytes) tuples."""
    records = []
    with open(path, "rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            raise ValueError("File too short to be a valid pcap")
        magic = struct.unpack("<I", global_header[:4])[0]
        if magic != 0xA1B2C3D4:
            raise ValueError(f"Unrecognized pcap magic number: {hex(magic)}")

        while True:
            record_header = f.read(16)
            if len(record_header) < 16:
                break
            ts_sec, _, incl_len, _ = struct.unpack("<IIII", record_header)
            frame = f.read(incl_len)
            if len(frame) < incl_len:
                break
            records.append((ts_sec, frame))
    return records


def read_pcap_packets(path: str) -> list:
    """Returns just the raw frame bytes (back-compat helper)."""
    return [frame for _, frame in read_pcap_records(path)]


def parse_ethernet_frame(frame: bytes, timestamp: int = None) -> ParsedPacket:
    if len(frame) < 14:
        raise ValueError("Frame too short to contain an Ethernet header")
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != 0x0800:
        raise ValueError(f"Only IPv4 (ethertype 0x0800) is supported by this parser, got {hex(ethertype)}")

    ip_start = 14
    version_ihl = frame[ip_start]
    ihl = (version_ihl & 0x0F) * 4
    protocol_num = frame[ip_start + 9]
    src_ip = socket.inet_ntoa(frame[ip_start + 12: ip_start + 16])
    dst_ip = socket.inet_ntoa(frame[ip_start + 16: ip_start + 20])

    transport_start = ip_start + ihl

    if protocol_num == 6:  # TCP
        src_port, dst_port = struct.unpack("!HH", frame[transport_start:transport_start + 4])
        flags = frame[transport_start + 13]
        data_offset = (frame[transport_start + 12] >> 4) * 4
        payload = frame[transport_start + data_offset:]
        return ParsedPacket(src_ip=src_ip, dst_ip=dst_ip, protocol="TCP",
                             src_port=src_port, dst_port=dst_port, tcp_flags=flags,
                             payload=payload, timestamp=timestamp)

    if protocol_num == 17:  # UDP
        src_port, dst_port = struct.unpack("!HH", frame[transport_start:transport_start + 4])
        payload = frame[transport_start + 8:]
        return ParsedPacket(src_ip=src_ip, dst_ip=dst_ip, protocol="UDP",
                             src_port=src_port, dst_port=dst_port, payload=payload, timestamp=timestamp)

    return ParsedPacket(src_ip=src_ip, dst_ip=dst_ip, protocol="OTHER", timestamp=timestamp)


def parse_pcap(path: str) -> list:
    return [parse_ethernet_frame(frame, timestamp=ts) for ts, frame in read_pcap_records(path)]


def parse_dns_query_name(payload: bytes) -> str:
    """Extracts the queried domain name from a DNS query payload's question section."""
    if len(payload) < 12:
        return ""
    pos = 12
    labels = []
    while pos < len(payload) and payload[pos] != 0:
        length = payload[pos]
        pos += 1
        labels.append(payload[pos:pos + length].decode(errors="replace"))
        pos += length
    return ".".join(labels)
