#pragma once

#include "core/packet.h"
#include <string>
#include <functional>

#ifdef HAS_PCAP
#include <pcap.h>
#endif

namespace packet_analyzer::capture {

class CaptureInterface {
public:
    virtual ~CaptureInterface() = default;
    virtual bool open(const std::string& source) = 0;
    virtual void close() = 0;
    virtual core::PacketPtr next_packet() = 0;
};

class PcapReader : public CaptureInterface {
public:
    ~PcapReader() override { close(); }
    bool open(const std::string& filename) override;
    void close() override;
    core::PacketPtr next_packet() override;

private:
#ifdef HAS_PCAP
    pcap_t* handle_ = nullptr;
#endif
};

class LiveCapture : public CaptureInterface {
public:
    ~LiveCapture() override { close(); }
    bool open(const std::string& interface_name) override;
    void close() override;
    core::PacketPtr next_packet() override;

private:
#ifdef HAS_PCAP
    pcap_t* handle_ = nullptr;
#endif
};

} // namespace packet_analyzer::capture
