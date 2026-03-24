#pragma once

#include "types.h"

// -------------------------------------------------------------
//  PacketSource - Abstract interface for packet input
// -------------------------------------------------------------
class PacketSource {
public:
    virtual ~PacketSource() = default;

    // Open / connect to the source.  Returns false on failure.
    virtual bool open(const std::string& resource) = 0;

    // Fill `pkt` with the next available packet.
    // Returns false when the source is exhausted (EOF or capture stopped).
    virtual bool nextPacket(RawPacket& pkt) = 0;

    // Human-readable name for logging (e.g. "sample.pcap", "eth0")
    virtual std::string name() const = 0;

    virtual void close() = 0;
};
