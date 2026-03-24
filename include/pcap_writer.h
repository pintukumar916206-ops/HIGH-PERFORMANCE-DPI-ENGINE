#pragma once

#include "pcap_reader.h"
#include <cstdio>
#include <string>

// -------------------------------------------------------------
//  PcapWriter - Simple class to write PCAP files
// -------------------------------------------------------------
//  Must be accessed from a single thread only (the output thread).
//  Not thread-safe by design — caller is responsible for serialization.
class PcapWriter {
public:
    PcapWriter()  = default;
    ~PcapWriter() { close(); }

    // Create or truncate `filename` and write the PCAP global header.
    bool open(const std::string& filename,
              uint32_t snaplen  = 65535,
              uint32_t linktype = PCAP_LINK_ETHERNET);

    // Append one packet record (header + data) to the file.
    bool writePacket(const RawPacket& pkt);

    void close();
    bool isOpen() const noexcept { return fp_ != nullptr; }

private:
    FILE*       fp_       = nullptr;
    uint32_t    snaplen_  = 65535;
};
