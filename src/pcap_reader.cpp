#include "pcap_reader.h"
#include "packet_pool.h"
#include <cstring>
#include <stdexcept>

bool PcapReader::open(const std::string& filename) {
    filename_ = filename;
    fp_ = fopen(filename.c_str(), "rb");
    if (!fp_) return false;

    PcapGlobalHeader hdr{};
    if (fread(&hdr, sizeof(hdr), 1, fp_) != 1) {
        fclose(fp_); fp_ = nullptr;
        return false;
    }

    if (hdr.magic_number == PCAP_MAGIC_NATIVE) {
        byte_swap_ = false;
    } else if (hdr.magic_number == PCAP_MAGIC_SWAPPED) {
        byte_swap_ = true;
    } else {
        fclose(fp_); fp_ = nullptr;
        return false;   // not a PCAP file
    }

    snaplen_  = swap32(hdr.snaplen);
    linktype_ = swap32(hdr.network);
    pkt_seq_  = 0;
    return true;
}

bool PcapReader::nextPacket(RawPacket& pkt) {
    if (!fp_) return false;

    PcapPacketHeader phdr{};
    if (fread(&phdr, sizeof(phdr), 1, fp_) != 1) return false;

    uint32_t incl = swap32(phdr.incl_len);
    uint32_t orig = swap32(phdr.orig_len);

    // Sanity guard — corrupt files can have absurd lengths
    if (incl > 65535) return false;

    // Lease a fresh buffer from the zero-copy pool
    pkt = PacketPool::instance().lease();
    if (pkt.empty()) return false;

    if (fread(pkt.data, 1, incl, fp_) != incl) {
        PacketPool::instance().release(pkt);
        return false;
    }
    pkt.len = incl;

    pkt.ts_sec   = swap32(phdr.ts_sec);
    pkt.ts_usec  = swap32(phdr.ts_usec);
    pkt.orig_len = orig;
    pkt.seq_num  = ++pkt_seq_;
    return true;
}

void PcapReader::close() {
    if (fp_) { fclose(fp_); fp_ = nullptr; }
}
