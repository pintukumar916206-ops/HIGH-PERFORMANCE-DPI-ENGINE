#pragma once

#include "packet.h"
#include <array>
#include <functional>
#include <cstring>

namespace packet_analyzer
{
    namespace core
    {

        struct FlowKey
        {
            uint32_t src_ip_v4 = 0;
            uint32_t dst_ip_v4 = 0;
            std::array<uint8_t, 16> src_ip_v6{};
            std::array<uint8_t, 16> dst_ip_v6{};
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            uint8_t protocol = 0;   // TCP=6, UDP=17
            uint8_t ip_version = 0; // 4 or 6

            bool operator==(const FlowKey &other) const
            {
                if (ip_version != other.ip_version || src_port != other.src_port ||
                    dst_port != other.dst_port || protocol != other.protocol)
                    return false;

                if (ip_version == 4)
                    return src_ip_v4 == other.src_ip_v4 && dst_ip_v4 == other.dst_ip_v4;
                else
                    return src_ip_v6 == other.src_ip_v6 && dst_ip_v6 == other.dst_ip_v6;
            }

            // Fast hash for sharding - NOT for std::hash, used manually
            uint32_t compute_hash() const
            {
                uint32_t h = 5381;
                if (ip_version == 4)
                {
                    h = ((h << 5) + h) ^ (src_ip_v4 & 0xFFFF);
                    h = ((h << 5) + h) ^ (src_ip_v4 >> 16);
                    h = ((h << 5) + h) ^ (dst_ip_v4 & 0xFFFF);
                    h = ((h << 5) + h) ^ (dst_ip_v4 >> 16);
                }
                else
                {
                    for (int i = 0; i < 16; i++)
                        h = ((h << 5) + h) ^ src_ip_v6[i];
                }
                h = ((h << 5) + h) ^ src_port;
                h = ((h << 5) + h) ^ dst_port;
                h = ((h << 5) + h) ^ protocol;
                return h;
            }
        };

        struct FlowKeyHash
        {
            std::size_t operator()(const FlowKey &k) const
            {
                return k.compute_hash();
            }
        };

        class Flow
        {
        public:
            Flow(const FlowKey &key) : key_(key) {}

            const FlowKey &key() const { return key_; }

            void update(const Packet &packet);

            size_t packet_count() const { return packet_count_; }
            size_t byte_count() const { return byte_count_; }
            auto start_time() const { return start_time_; }
            auto last_seen() const { return last_seen_; }

        private:
            FlowKey key_;
            size_t packet_count_ = 0;
            size_t byte_count_ = 0;
            std::chrono::system_clock::time_point start_time_;
            std::chrono::system_clock::time_point last_seen_;
        };

    } // namespace core
} // namespace packet_analyzer
