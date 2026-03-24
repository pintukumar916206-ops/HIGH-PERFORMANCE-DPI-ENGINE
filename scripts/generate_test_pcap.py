#!/usr/bin/env python3
"""
generate_test_pcap.py  \u2014  Generates a rich synthetic .pcap for DPI testing.

Writes real Ethernet/IPv4/TCP/UDP frames with:
  - TLS ClientHello packets with SNI for YouTube, Facebook, Netflix, GitHub, etc.
  - HTTP GET requests with Host headers
  - DNS queries and responses
  - BitTorrent handshakes
  - SSH connection attempts
  - SMTP banner
  - Malformed / truncated packets (for robustness testing)

Usage:
  python3 generate_test_pcap.py             # writes test_dpi.pcap
  python3 generate_test_pcap.py out.pcap    # custom output name
"""

import struct
import socket
import random
import sys
import os

def write_pcap_header(f):
    # Global header (24 bytes)
    # magic, major, minor, zone, sigfigs, snaplen, network
    f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

def write_packet(f, data, sec=0, usec=0):
    # Packet header (16 bytes)
    # ts_sec, ts_usec, incl_len, orig_len
    f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
    f.write(data)

def build_eth_ipv4_tcp(src_ip, dst_ip, src_port, dst_port, payload=b"", flags=0x02):
    # Ethernet
    eth = b"\x00\x00\x00\x00\x00\x02" + b"\x00\x00\x00\x00\x00\x01" + b"\x08\x00"
    
    # IPv4
    ihl = 5
    total_len = 20 + 20 + len(payload)
    ip_hdr = struct.pack("!BBHHHBBHII", 
        (4 << 4) | ihl, 0, total_len, random.randint(0, 65535), 0, 64, 6, 0,
        struct.unpack("!I", socket.inet_aton(src_ip))[0],
        struct.unpack("!I", socket.inet_aton(dst_ip))[0]
    )
    
    # TCP
    tcp_hdr = struct.pack("!HHIIBBHHH",
        src_port, dst_port, random.randint(0, 0xFFFFFFFF), 0, (5 << 4), flags, 8192, 0, 0
    )
    
    return eth + ip_hdr + tcp_hdr + payload

def build_eth_ipv4_udp(src_ip, dst_ip, src_port, dst_port, payload=b""):
    eth = b"\x00\x00\x00\x00\x00\x02" + b"\x00\x00\x00\x00\x00\x01" + b"\x08\x00"
    total_len = 20 + 8 + len(payload)
    ip_hdr = struct.pack("!BBHHHBBHII", 
        (4 << 4) | 5, 0, total_len, random.randint(0, 65535), 0, 64, 17, 0,
        struct.unpack("!I", socket.inet_aton(src_ip))[0],
        struct.unpack("!I", socket.inet_aton(dst_ip))[0]
    )
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return eth + ip_hdr + udp_hdr + payload

def build_tls_client_hello(sni):
    # Extension: SNI
    sni_bytes = sni.encode('ascii')
    name_len = len(sni_bytes)
    # list_len (2) + type (1) + host_len (2) + host (N)
    sni_ext = struct.pack("!HHBH", 0x0000, 2 + 1 + 2 + name_len, 2 + 1 + 2 + name_len - 2, 0x00) + struct.pack("!H", name_len) + sni_bytes
    
    exts = sni_ext
    # rest of ClientHello...
    ch = struct.pack("!H", 0x0303) + b"\xAB"*32 + b"\x00" # ver, rand, sessid_len
    ch += struct.pack("!H", 2) + b"\xC0\x2B" # cipher suites
    ch += b"\x01\x00" # compression
    ch += struct.pack("!H", len(exts)) + exts
    
    # Handshake header
    hs = struct.pack("!B", 0x01) + struct.pack("!I", len(ch))[1:] + ch
    # Record header
    rec = struct.pack("!BHH", 0x16, 0x0301, len(hs)) + hs
    return rec

def main():
    outfile = sys.argv[1] if len(sys.argv) > 1 else "test_dpi.pcap"
    with open(outfile, "wb") as f:
        write_pcap_header(f)
        total = 0
        
        # 1. TLS Flows with SNI
        services = [
            ("142.250.185.206", "www.youtube.com"),
            ("157.240.1.35",    "www.facebook.com"),
            ("198.45.48.56",    "www.netflix.com"),
            ("140.82.121.4",    "github.com"),
            ("104.244.42.65",   "twitter.com"),
            ("31.13.92.36",     "instagram.com"),
            ("52.6.183.74",     "www.amazon.com"),
            ("40.76.4.15",      "microsoft.com"),
            ("104.16.124.96",   "cloudflare.com")
        ]
        
        for i, (dip, sni) in enumerate(services):
            sip = f"192.168.1.{10+i}"
            sp  = 54001 + i
            # Handshake (SYN, SYN-ACK, ACK, ClientHello)
            write_packet(f, build_eth_ipv4_tcp(sip, dip, sp, 443, b"", 0x02), i)
            write_packet(f, build_eth_ipv4_tcp(dip, sip, 443, sp, b"", 0x12), i)
            write_packet(f, build_eth_ipv4_tcp(sip, dip, sp, 443, b"", 0x10), i)
            write_packet(f, build_eth_ipv4_tcp(sip, dip, sp, 443, build_tls_client_hello(sni), 0x18), i)
            # Add some data flow
            for j in range(5):
                write_packet(f, build_eth_ipv4_tcp(dip, sip, 443, sp, b"D"*random.randint(50, 200), 0x18), i+j)
            total += 9

        # 2. HTTP Flow
        sip, dip = "192.168.1.50", "93.184.216.34"
        write_packet(f, build_eth_ipv4_tcp(sip, dip, 55555, 80, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"), 20)
        total += 1
        
        # 3. BitTorrent Handshake
        bt_payload = b"\x13BitTorrent protocol" + b"\x00"*8 + b"H"*20 + b"P"*20
        write_packet(f, build_eth_ipv4_tcp("192.168.1.60", "192.168.1.100", 57001, 6881, bt_payload), 25)
        total += 1

        # 4. DNS
        for i in range(3):
            dns = struct.pack("!HHHHHH", i, 0x0100, 1, 0, 0, 0) + b"\x06google\x03com\x00\x00\x01\x00\x01"
            write_packet(f, build_eth_ipv4_udp("192.168.1.10", "8.8.8.8", 12345+i, 53, dns), 30+i)
            write_packet(f, build_eth_ipv4_udp("8.8.8.8", "192.168.1.10", 53, 12345+i, dns + b"ANS"), 30+i)
            total += 2

        # 5. Malformed
        f.write(struct.pack("<IIII", 40, 0, 10, 1024)) # header says 10 bytes incl, 1024 orig
        f.write(b"NOT_A_PKT")
        total += 1

        print(f"[+] Written {total} packets to {outfile}")

if __name__ == "__main__":
    main()
