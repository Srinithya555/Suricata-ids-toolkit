"""
Writes packets to the classic libpcap file format (the same format
Wireshark/tcpdump produce), using only `struct` — no library dependency.
Format reference: the file starts with a 24-byte global header, followed
by a (16-byte record header + raw packet bytes) pair per packet.
"""
import struct
import time

PCAP_MAGIC = 0xA1B2C3D4  # standard magic number, indicates microsecond timestamps + native byte order
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
LINKTYPE_ETHERNET = 1


def write_pcap(path: str, packets: list, timestamps: list = None) -> None:
    """
    packets: list of raw bytes, each a full Ethernet frame.
    timestamps: optional list of integer second offsets (same length as
    packets) for controlling exact packet timing — needed to test
    time-windowed detection logic (e.g. "5 SYNs within 10 seconds")
    deterministically rather than relying on wall-clock time. If not
    given, packets are spaced 1 second apart in the order given.
    """
    with open(path, "wb") as f:
        global_header = struct.pack(
            "<IHHiIII",
            PCAP_MAGIC, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
            0, 0, 65535, LINKTYPE_ETHERNET,
        )
        f.write(global_header)

        base_time = int(time.time())
        for i, packet in enumerate(packets):
            ts_sec = base_time + (timestamps[i] if timestamps else i)
            ts_usec = 0
            record_header = struct.pack("<IIII", ts_sec, ts_usec, len(packet), len(packet))
            f.write(record_header)
            f.write(packet)
