#pragma once

#include "types.h"

class PacketParser {
public:
    static bool parse(const RawPacket& raw, ParsedPacket& out);

private:
    static size_t parseEthernet(const uint8_t* data, size_t len,
                                ParsedPacket& out);

    static size_t parseIPv4    (const uint8_t* data, size_t len,
                                size_t offset, ParsedPacket& out);

    static size_t parseIPv6    (const uint8_t* data, size_t len,
                                size_t offset, ParsedPacket& out);

    static size_t parseTCP     (const uint8_t* data, size_t len,
                                size_t offset, ParsedPacket& out);

    static size_t parseUDP     (const uint8_t* data, size_t len,
                                size_t offset, ParsedPacket& out);

    static void   parseICMP    (const uint8_t* data, size_t len,
                                size_t offset, ParsedPacket& out);

    static inline uint16_t read16be(const uint8_t* p) noexcept {
        return (uint16_t(p[0]) << 8) | p[1];
    }
    static inline uint32_t read32be(const uint8_t* p) noexcept {
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
               (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
    }
};