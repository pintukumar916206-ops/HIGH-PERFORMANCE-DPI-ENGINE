#pragma once

#include "pcap_reader.h"
#include <cstdio>
#include <string>

class PcapWriter {
public:
    PcapWriter()  = default;
    ~PcapWriter() { close(); }

    bool open(const std::string& filename,
              uint32_t snaplen  = 65535,
              uint32_t linktype = PCAP_LINK_ETHERNET);

    bool writePacket(const RawPacket& pkt);

    void close();
    bool isOpen() const noexcept { return fp_ != nullptr; }

private:
    FILE*       fp_       = nullptr;
    uint32_t    snaplen_  = 65535;
};
