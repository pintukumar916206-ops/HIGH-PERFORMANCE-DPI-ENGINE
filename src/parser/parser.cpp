#include "parser/parser.h"
#include "utils/endian.h"
#include <cstring>

namespace packet_analyzer::parser {

using namespace utils;

bool Parser::parse(core::Packet& packet) {
    const auto& raw = packet.raw();
    size_t offset = 0;
    return parse_ethernet(packet, raw.data.data(), raw.data.size(), offset);
}

bool Parser::parse_ethernet(core::Packet& packet, const uint8_t* data, size_t len, size_t& offset) {
    if (len < 14) return false;

    auto& meta = packet.metadata();
    
    // Store MAC addresses as binary (no conversion to string until output)
    std::memcpy(meta.dst_mac.data(), data, 6);
    std::memcpy(meta.src_mac.data(), data + 6, 6);
    
    uint16_t ether_type = net_to_host16(*reinterpret_cast<const uint16_t*>(data + 12));
    offset = 14;

    // Handle VLAN tags (802.1Q and 802.1ad)
    while (ether_type == 0x8100 || ether_type == 0x88a8) {
        if (len < offset + 4) return false;  // VLAN tag is 4 bytes
        ether_type = net_to_host16(*reinterpret_cast<const uint16_t*>(data + offset + 2));
        offset += 4;
    }

    meta.ether_type = ether_type;

    if (ether_type == 0x0800) {  // IPv4
        return parse_ipv4(packet, data, len, offset);
    } else if (ether_type == 0x86DD) {  // IPv6
        return parse_ipv6(packet, data, len, offset);
    }

    return true;
}

bool Parser::parse_ipv4(core::Packet& packet, const uint8_t* data, size_t len, size_t& offset) {
    if (len < offset + 20) return false;
    
    const uint8_t* ip_header = data + offset;
    uint8_t ihl = (ip_header[0] & 0x0F) * 4;
    if (len < offset + ihl) return false;

    auto& meta = packet.metadata();
    meta.has_ip = true;
    meta.ip_version = 4;
    
    // Store as binary (network byte order - no conversion)
    std::memcpy(&meta.src_ip_v4, ip_header + 12, 4);
    std::memcpy(&meta.dst_ip_v4, ip_header + 16, 4);
    
    meta.protocol = ip_header[9];

    offset += ihl;

    if (meta.protocol == 6) {  // TCP
        return parse_tcp(packet, data, len, offset);
    } else if (meta.protocol == 17) {  // UDP
        return parse_udp(packet, data, len, offset);
    }

    return true;
}

bool Parser::parse_ipv6(core::Packet& packet, const uint8_t* data, size_t len, size_t& offset) {
    if (len < offset + 40) return false;
    
    auto& meta = packet.metadata();
    meta.has_ip = true;
    meta.ip_version = 6;
    meta.protocol = data[offset + 6];  // Next Header
    
    // Store IPv6 addresses as binary
    std::memcpy(meta.src_ip_v6.data(), data + offset + 8, 16);
    std::memcpy(meta.dst_ip_v6.data(), data + offset + 24, 16);

    offset += 40;
    
    if (meta.protocol == 6) return parse_tcp(packet, data, len, offset);
    if (meta.protocol == 17) return parse_udp(packet, data, len, offset);
    
    return true;
}

bool Parser::parse_tcp(core::Packet& packet, const uint8_t* data, size_t len, size_t& offset) {
    if (len < offset + 20) return false;

    const uint8_t* tcp_header = data + offset;
    auto& meta = packet.metadata();
    meta.has_transport = true;
    meta.src_port = net_to_host16(*reinterpret_cast<const uint16_t*>(tcp_header));
    meta.dst_port = net_to_host16(*reinterpret_cast<const uint16_t*>(tcp_header + 2));
    meta.tcp_flags = tcp_header[13];

    uint8_t data_offset = (tcp_header[12] >> 4) * 4;
    offset += data_offset;
    
    if (len > offset) {
        meta.payload = data + offset;
        meta.payload_len = len - offset;
    }

    return true;
}

bool Parser::parse_udp(core::Packet& packet, const uint8_t* data, size_t len, size_t& offset) {
    if (len < offset + 8) return false;

    const uint8_t* udp_header = data + offset;
    auto& meta = packet.metadata();
    meta.has_transport = true;
    meta.src_port = net_to_host16(*reinterpret_cast<const uint16_t*>(udp_header));
    meta.dst_port = net_to_host16(*reinterpret_cast<const uint16_t*>(udp_header + 2));

    offset += 8;
    
    if (len > offset) {
        meta.payload = data + offset;
        meta.payload_len = len - offset;
    }

    return true;
}

// Format functions (for output only, NOT used in engine)
std::string Parser::mac_to_string(const std::array<uint8_t, 6>& mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

std::string Parser::ipv4_to_string(uint32_t ip) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&ip);
    char buf[16];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
    return std::string(buf);
}

} // namespace packet_analyzer::parser
