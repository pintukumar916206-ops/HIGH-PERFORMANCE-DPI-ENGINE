#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <chrono>
#include <memory>
#include <array>

namespace packet_analyzer
{
    namespace core
    {

        // Non-owning view into pcap mmap buffer: zero-copy
        // Valid only during pcap callback scope
        struct RawPacket
        {
            const uint8_t *data;      // pointer into pcap mmap ring
            uint32_t len;             // captured length
            struct timeval timestamp; // from pcap_pkthdr
        };

        // Binary representation - NO strings until output formatting
        struct PacketMetadata
        {
            // L2 - All binary
            std::array<uint8_t, 6> src_mac{};
            std::array<uint8_t, 6> dst_mac{};
            uint16_t ether_type = 0;

            // L3 - Binary representation
            bool has_ip = false;
            uint8_t ip_version = 0;
            uint32_t src_ip_v4 = 0; // Network byte order
            uint32_t dst_ip_v4 = 0; // Network byte order
            std::array<uint8_t, 16> src_ip_v6{};
            std::array<uint8_t, 16> dst_ip_v6{};
            uint8_t protocol = 0; // TCP=6, UDP=17

            // L4 - Binary
            bool has_transport = false;
            uint16_t src_port = 0;
            uint16_t dst_port = 0;
            uint8_t tcp_flags = 0;

            // L7 / DPI - Protocol as enum, metadata as offsets + lengths
            enum class AppProtocol : uint8_t
            {
                UNKNOWN = 0,
                HTTP = 1,
                TLS = 2,
                DNS = 3,
                QUIC = 4
            };

            AppProtocol app_protocol = AppProtocol::UNKNOWN;

            // For HTTP: extracted Host header value
            std::string http_host{};

            // For TLS: extracted SNI
            std::string sni{};

            // For DNS: parsed header fields
            uint16_t dns_transaction_id = 0;
            uint16_t dns_question_count = 0;
            uint8_t dns_flags = 0;

            // Payload pointer (valid only during parsing in callback)
            const uint8_t *payload = nullptr;
            size_t payload_len = 0;
        };

        class Packet
        {
        public:
            // Constructor from RawPacket view (used during callback only)
            Packet() : processing_start_time_(std::chrono::steady_clock::now()) {}

            // RawPacket is a view — not stored long-term
            // Parsing happens synchronously during pcap callback
            const PacketMetadata &metadata() const { return metadata_; }
            PacketMetadata &metadata() { return metadata_; }

            auto get_processing_start_time() const { return processing_start_time_; }
            uint64_t get_processing_duration_us() const
            {
                auto now = std::chrono::steady_clock::now();
                return std::chrono::duration_cast<std::chrono::microseconds>(
                           now - processing_start_time_)
                    .count();
            }

        private:
            PacketMetadata metadata_;
            std::chrono::steady_clock::time_point processing_start_time_;
        };

        using PacketPtr = std::unique_ptr<Packet>;

    } // namespace core
} // namespace packet_analyzer
