#pragma once

#include "core/packet.h"
#include <string>
#include <array>

namespace packet_analyzer::parser
{

    class Parser
    {
    public:
        static bool parse(core::Packet &packet, const core::RawPacket &raw);

        // Format functions - ONLY for output, not used in engine processing
        static std::string mac_to_string(const std::array<uint8_t, 6> &mac);
        static std::string ipv4_to_string(uint32_t ip);

    private:
        static bool parse_ethernet(core::Packet &packet, const uint8_t *data, size_t len, size_t &offset);
        static bool parse_ipv4(core::Packet &packet, const uint8_t *data, size_t len, size_t &offset);
        static bool parse_ipv6(core::Packet &packet, const uint8_t *data, size_t len, size_t &offset);
        static bool parse_tcp(core::Packet &packet, const uint8_t *data, size_t len, size_t &offset);
        static bool parse_udp(core::Packet &packet, const uint8_t *data, size_t len, size_t &offset);

        // Protocol validators (structural checks, not just port numbers)
        static bool is_real_dns(const uint8_t *payload, uint32_t len);
        static bool is_real_http(const uint8_t *payload, uint32_t len);
        static bool is_real_tls(const uint8_t *payload, uint32_t len);
        static bool is_real_quic(const uint8_t *payload, uint32_t len);
    };

} // namespace packet_analyzer::parser
