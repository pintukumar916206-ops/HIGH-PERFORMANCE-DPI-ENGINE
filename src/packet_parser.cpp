#include "packet_parser.h"
#include <cstring>

// Ethernet header is always exactly 14 bytes (6+6+2) for standard frames.
// 802.1Q VLAN-tagged frames insert an extra 4 bytes at offset 12.
static constexpr size_t ETH_HEADER_LEN = 14;
static constexpr size_t IPV4_MIN_LEN   = 20;
static constexpr size_t TCP_MIN_LEN    = 20;
static constexpr size_t UDP_HEADER_LEN =  8;
static constexpr size_t ICMP_MIN_LEN   =  4;

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& out) {
    out = ParsedPacket{};   // zero-init every field
    out.valid = false;

    if (raw.empty()) return false;
    const uint8_t* data = raw.data;
    const size_t   len  = raw.len;

    if (len < ETH_HEADER_LEN) return false;  // not even an Ethernet frame

    // Store raw reference metadata so the caller can get timestamps etc.
    out.raw.ts_sec  = raw.ts_sec;
    out.raw.ts_usec = raw.ts_usec;
    out.raw.seq_num = raw.seq_num;
    out.tuple = {};

    size_t offset = parseEthernet(data, len, out);
    if (offset == 0) return false;

    // Process IPv4 or IPv6
    if (!out.has_ip && !out.is_ipv6) {
        out.valid = true;
        return true;
    }

    // Select L4 parser based on IP protocol field
    size_t payload_offset = 0;
    if (out.ip_proto == proto::TCP && !out.is_fragment) {
        payload_offset = parseTCP(data, len, offset, out);
    } else if (out.ip_proto == proto::UDP) {
        payload_offset = parseUDP(data, len, offset, out);
    } else if (out.ip_proto == proto::ICMP) {
        parseICMP(data, len, offset, out);
        out.has_icmp = true;
        out.valid = true;
        return true;
    }

    // Set the payload pointer (zero-copy — points into raw.data)
    if (payload_offset > 0 && payload_offset <= len) {
        out.payload     = data + payload_offset;
        out.payload_len = len  - payload_offset;
    }

    // Build the FiveTuple for routing and flow lookup
    out.tuple.protocol = out.ip_proto;
    out.tuple.is_ipv6  = out.is_ipv6;
    if (out.is_ipv6) {
        std::memcpy(out.tuple.src_ip, out.src_ip6, 16);
        std::memcpy(out.tuple.dst_ip, out.dst_ip6, 16);
    } else {
        out.tuple.setIPv4(out.src_ip, out.dst_ip);
    }
    out.tuple.src_port = out.src_port;
    out.tuple.dst_port = out.dst_port;

    out.valid = true;
    return true;
}

// Ethernet Parsing
size_t PacketParser::parseEthernet(const uint8_t* data, size_t len,
                                   ParsedPacket& out) {
    if (len < ETH_HEADER_LEN) return 0;

    std::memcpy(out.dst_mac, data,     6);
    std::memcpy(out.src_mac, data + 6, 6);
    uint16_t etype = read16be(data + 12);

    size_t offset = ETH_HEADER_LEN;

    // Handle 802.1Q VLAN tagging: skip the 4-byte VLAN header
    if (etype == 0x8100) {
        if (len < offset + 4) return 0;
        etype   = read16be(data + offset + 2);
        offset += 4;
    }

    out.eth_type = etype;

    if (etype == proto::ETH_IPV4) {
        if (len < offset + IPV4_MIN_LEN) return 0;
        out.has_ip = true;
        return parseIPv4(data, len, offset, out);
    }

    if (etype == proto::ETH_IPV6) {
        if (len < offset + 40) return 0;
        out.is_ipv6 = true;
        return parseIPv6(data, len, offset, out);
    }

    if (etype == proto::ETH_ARP) {
        out.app_type = AppType::ARP;
    }
    return offset;
}

// IPv4 Parsing
size_t PacketParser::parseIPv4(const uint8_t* data, size_t len,
                               size_t offset, ParsedPacket& out) {
    if (offset + IPV4_MIN_LEN > len) return 0;

    const uint8_t* ip = data + offset;

    uint8_t  ihl      = (ip[0] & 0x0F) * 4;   // header length in bytes
    if (ihl < 20) return 0;                     // IHL < 5 is illegal

    out.ip_total_len  = read16be(ip + 2);
    out.ip_id         = read16be(ip + 4);
    out.ttl           = ip[8];
    out.ip_proto      = ip[9];

    // Fragment check: MF bit set, or fragment offset non-zero
    uint16_t frag_info = read16be(ip + 6);
    out.is_fragment = ((frag_info & 0x2000) != 0) ||  // More Fragments
                      ((frag_info & 0x1FFF) != 0);    // Fragment Offset

    out.src_ip = read32be(ip + 12);
    out.dst_ip = read32be(ip + 16);

    return offset + ihl;   // offset of L4 header
}

// TCP Parsing
size_t PacketParser::parseTCP(const uint8_t* data, size_t len,
                              size_t offset, ParsedPacket& out) {
    if (offset + TCP_MIN_LEN > len) return 0;

    const uint8_t* tcp = data + offset;

    out.has_tcp      = true;
    out.src_port     = read16be(tcp + 0);
    out.dst_port     = read16be(tcp + 2);
    out.tcp_seq      = read32be(tcp + 4);
    out.tcp_ack_num  = read32be(tcp + 8);
    out.tcp_flags    = tcp[13];
    out.window_size  = read16be(tcp + 14);

    uint8_t data_offset = (tcp[12] >> 4) * 4;  // TCP header length in bytes
    if (data_offset < 20) return 0;             // Data Offset < 5 is illegal

    return offset + data_offset;   // offset of application payload
}

// UDP Parsing
size_t PacketParser::parseUDP(const uint8_t* data, size_t len,
                              size_t offset, ParsedPacket& out) {
    if (offset + UDP_HEADER_LEN > len) return 0;

    const uint8_t* udp = data + offset;

    out.has_udp  = true;
    out.src_port = read16be(udp + 0);
    out.dst_port = read16be(udp + 2);
    // udp[4..5] = length, udp[6..7] = checksum — not needed here

    return offset + UDP_HEADER_LEN;
}

// IPv6 Parsing
size_t PacketParser::parseIPv6(const uint8_t* data, size_t len,
                               size_t offset, ParsedPacket& out) {
    if (offset + 40 > len) return 0;
    const uint8_t* ip6 = data + offset;

    // Traffic Class / Flow Label (first 4 bytes) - skipped for now
    out.ip_total_len = read16be(ip6 + 4); // payload length
    uint8_t next_hdr = ip6[6];
    out.ttl          = ip6[7]; // hop limit

    std::memcpy(out.src_ip6, ip6 + 8, 16);
    std::memcpy(out.dst_ip6, ip6 + 24, 16);

    offset += 40;

    // Extension Headers traversal
    while (offset < len) {
        if (next_hdr == proto::TCP || next_hdr == proto::UDP || next_hdr == proto::ICMP) {
            break; 
        }
        // Simplified extension header skip (Hdr Ext Len field is at byte 1)
        if (offset + 8 > len) break;
        uint8_t ext_len = (data[offset + 1] + 1) * 8;
        next_hdr = data[offset];
        offset += ext_len;
    }

    out.ip_proto = next_hdr;
    return offset;
}

// ICMP Parsing
void PacketParser::parseICMP(const uint8_t* data, size_t len,
                             size_t offset, ParsedPacket& out) {
    if (offset + ICMP_MIN_LEN > len) return;
    out.app_type = AppType::ICMP;
}
