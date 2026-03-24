#pragma once

#include "types.h"

// -------------------------------------------------------------
//  PacketParser
// -------------------------------------------------------------
//  PacketParser  —  stateless, zero-copy protocol decoder
//
//  Parses raw Ethernet frames into a ParsedPacket structure.
//  The payload pointer inside ParsedPacket points directly into
//  the RawPacket's data buffer — no copies are made.
//
//  All header offsets are computed dynamically from the IHL/DataOffset
//  fields, so variable-length headers (IP options, TCP options) are
//  handled correctly without hardcoded offsets.
//
//  Design choice — static methods only:
//    A parser holds no state between calls.  Making it a collection
//    of static methods rather than a singleton/global avoids any
//    initialization-order or threading concern.
// -------------------------------------------------------------
class PacketParser {
public:
    // Parse a raw Ethernet frame.  Returns true when the result is
    // useful (has at minimum a valid IPv4 header).
    static bool parse(const RawPacket& raw, ParsedPacket& out);

private:
    // Each sub-parser returns the byte offset AFTER its own header,
    // i.e. the start of the next layer's data.
    // Returns 0 on a malformed/truncated header.
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

    // Big-endian memory reads — avoids platform-specific ntohs/ntohl
    // and unaligned-access UB.
    static inline uint16_t read16be(const uint8_t* p) noexcept {
        return (uint16_t(p[0]) << 8) | p[1];
    }
    static inline uint32_t read32be(const uint8_t* p) noexcept {
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
               (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
    }
};
