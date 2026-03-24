#pragma once

#include "core/packet.h"
#include <vector>

namespace packet_analyzer::engine
{

    class DpiEngine
    {
    public:
        static void process(core::Packet &packet);

    private:
        static bool detect_http(core::Packet &packet, uint32_t payload_offset);
        static bool detect_tls(core::Packet &packet, uint32_t payload_offset);
        static bool detect_dns(core::Packet &packet, uint32_t payload_offset);
        static bool detect_quic(core::Packet &packet);
    };

    struct Rule
    {
        uint32_t ipv4_src = 0; // Binary IPv4 (0 = any)
        uint32_t ipv4_dst = 0; // Binary IPv4 (0 = any)
        uint16_t port = 0;     // Port (0 = any)
        uint8_t protocol = 0;  // Protocol (0 = any)
        bool block = false;    // Action
    };

    class RuleEngine
    {
    public:
        void add_rule(const Rule &rule) { rules_.push_back(rule); }
        bool should_block(const core::Packet &packet) const;

    private:
        std::vector<Rule> rules_;
    };

} // namespace packet_analyzer::engine
