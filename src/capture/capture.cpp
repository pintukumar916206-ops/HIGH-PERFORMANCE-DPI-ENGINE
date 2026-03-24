#include "capture/capture.h"
#include <iostream>

namespace packet_analyzer::capture {

bool PcapReader::open(const std::string& filename) {
#ifdef HAS_PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_offline(filename.c_str(), errbuf);
    if (!handle_) {
        std::cerr << "pcap_open_offline error: " << errbuf << std::endl;
        return false;
    }
    return true;
#else
    std::cerr << "PcapReader: libpcap not available" << std::endl;
    return false;
#endif
}

void PcapReader::close() {
#ifdef HAS_PCAP
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
#endif
}

core::PacketPtr PcapReader::next_packet() {
#ifdef HAS_PCAP
    struct pcap_pkthdr* header;
    const u_char* data;
    int res = pcap_next_ex(handle_, &header, &data);
    
    if (res != 1) return nullptr;

    core::RawPacket raw;
    raw.data.assign(data, data + header->caplen);
    raw.original_length = header->len;
    raw.timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec) + 
                    std::chrono::microseconds(header->ts.tv_usec);

    return std::make_unique<core::Packet>(std::move(raw));
#else
    return nullptr;
#endif
}

bool LiveCapture::open(const std::string& interface_name) {
#ifdef HAS_PCAP
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(interface_name.c_str(), 65535, 1, 1000, errbuf);
    if (!handle_) {
        std::cerr << "pcap_open_live error: " << errbuf << std::endl;
        return false;
    }
    return true;
#else
    std::cerr << "LiveCapture: libpcap not available" << std::endl;
    return false;
#endif
}

void LiveCapture::close() {
#ifdef HAS_PCAP
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
#endif
}

core::PacketPtr LiveCapture::next_packet() {
#ifdef HAS_PCAP
    struct pcap_pkthdr* header;
    const u_char* data;
    int res = pcap_next_ex(handle_, &header, &data);
    
    if (res != 1) return nullptr;

    core::RawPacket raw;
    raw.data.assign(data, data + header->caplen);
    raw.original_length = header->len;
    raw.timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec) + 
                    std::chrono::microseconds(header->ts.tv_usec);

    return std::make_unique<core::Packet>(std::move(raw));
#else
    return nullptr;
#endif
}

} // namespace packet_analyzer::capture
