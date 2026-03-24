#include "pcap_writer.h"
#include <cstring>

bool PcapWriter::open(const std::string& filename,
                      uint32_t snaplen,
                      uint32_t linktype) {
    snaplen_ = snaplen;
    fp_ = fopen(filename.c_str(), "wb");
    if (!fp_) return false;

    PcapGlobalHeader hdr{};
    hdr.magic_number  = PCAP_MAGIC_NATIVE;
    hdr.v_maj = 2;
    hdr.v_min = 4;
    hdr.thiszone      = 0;
    hdr.sigfigs       = 0;
    hdr.snaplen       = snaplen;
    hdr.network       = linktype;

    if (fwrite(&hdr, sizeof(hdr), 1, fp_) != 1) {
        fclose(fp_); fp_ = nullptr;
        return false;
    }
    return true;
}

bool PcapWriter::writePacket(const RawPacket& pkt) {
    if (!fp_) return false;

    uint32_t incl = pkt.len;
    if (incl > snaplen_) incl = snaplen_;

    PcapPacketHeader phdr{};
    phdr.ts_sec   = pkt.ts_sec;
    phdr.ts_usec  = pkt.ts_usec;
    phdr.incl_len = incl;
    phdr.orig_len = pkt.orig_len > 0 ? pkt.orig_len
                                     : pkt.len;

    if (fwrite(&phdr, sizeof(phdr), 1, fp_) != 1) return false;
    if (fwrite(pkt.data, 1, incl, fp_) != incl) return false;
    return true;
}

void PcapWriter::close() {
    if (fp_) { fflush(fp_); fclose(fp_); fp_ = nullptr; }
}
