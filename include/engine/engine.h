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
        uint32_t ipv4_src = 0;
        uint32_t ipv4_dst = 0;
        uint16_t port = 0;
        uint8_t protocol = 0;
        bool block = false;
    };

    class RuleEngine
    {
    public:
        void add_rule(const Rule &rule) { rules_.push_back(rule); }
        bool should_block(const core::Packet &packet) const;

    private:
        std::vector<Rule> rules_;
    };

}