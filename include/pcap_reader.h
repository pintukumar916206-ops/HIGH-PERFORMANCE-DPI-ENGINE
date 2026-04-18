#pragma once

#include "packet_source.h"
#include <cstdio>
#include <string>

#pragma pack(push, 1)

struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t v_maj;
    uint16_t v_min;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

#pragma pack(pop)

constexpr uint32_t PCAP_MAGIC_NATIVE    = 0xa1b2c3d4;
constexpr uint32_t PCAP_MAGIC_SWAPPED   = 0xd4c3b2a1;
constexpr uint32_t PCAP_LINK_ETHERNET   = 1;

class PcapReader final : public PacketSource {
public:
    PcapReader()  = default;
    ~PcapReader() override { close(); }

    bool open(const std::string& filename) override;
    bool nextPacket(RawPacket& pkt) override;
    std::string name() const override { return filename_; }
    void close() override;

    uint32_t snaplen()  const noexcept { return snaplen_;  }
    uint32_t linktype() const noexcept { return linktype_; }

private:
    FILE*       fp_         = nullptr;
    std::string filename_;
    uint32_t    snaplen_    = 65535;
    uint32_t    linktype_   = PCAP_LINK_ETHERNET;
    bool        byte_swap_  = false;
    uint64_t    pkt_seq_    = 0;

    uint32_t swap32(uint32_t v) const noexcept {
        if (!byte_swap_) return v;
        return ((v & 0xFF000000) >> 24) |
               ((v & 0x00FF0000) >>  8) |
               ((v & 0x0000FF00) <<  8) |
               ((v & 0x000000FF) << 24);
    }
};