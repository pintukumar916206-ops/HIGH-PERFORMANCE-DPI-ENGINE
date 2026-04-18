#ifndef LIVE_CAPTURE_H
#define LIVE_CAPTURE_H

#include <string>
#include <functional>
#include <vector>
#include "packet.h"

class LiveCapture
{
public:
  using PacketCallback = std::function<void(const Packet &)>;

  struct Config
  {
    std::string interface;
    int packet_count = -1;
    int snaplen = 65535;
    int promisc = 1;
    int timeout_ms = 1000;
    int buffer_size_mb = 100;
  };

  LiveCapture() = default;
  ~LiveCapture();

  bool init(const Config &cfg);

  static std::vector<std::pair<std::string, std::string>> get_interfaces();

  bool start_capture(PacketCallback callback);

  void stop_capture();

  struct Stats
  {
    uint64_t packets_captured = 0;
    uint64_t packets_dropped = 0;
    uint64_t bytes_captured = 0;
  };
  Stats get_stats() const;

private:
  void *pcap_handle_ = nullptr;
  bool running_ = false;
  Config config_;
  Stats stats_;
};

#endif