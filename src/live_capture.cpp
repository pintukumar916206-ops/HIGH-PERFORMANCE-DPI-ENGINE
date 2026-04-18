#include "live_capture.h"
#include <iostream>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <pcap.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "wpcap.lib")
#else
#include <pcap.h>
#include <ifaddrs.h>
#endif

#include "utils/logger.h"
#include "core/packet.h"

LiveCapture::~LiveCapture()
{
  if (pcap_handle_)
  {
    pcap_close(static_cast<pcap_t *>(pcap_handle_));
    pcap_handle_ = nullptr;
  }
}

bool LiveCapture::init(const Config &cfg)
{
  config_ = cfg;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_live(
      cfg.interface.c_str(),
      cfg.snaplen,
      cfg.promisc,
      cfg.timeout_ms,
      errbuf);

  if (!handle)
  {
    LOG_ERROR("Failed to open interface '%s': %s", cfg.interface.c_str(), errbuf);
    return false;
  }

  if (pcap_setnonblock(handle, 1, errbuf) == -1)
  {
    LOG_WARN("Could not set non-blocking mode: %s", errbuf);
  }

#ifdef _WIN32

  if (cfg.buffer_size_mb > 0)
  {
    pcap_set_buff(handle, cfg.buffer_size_mb * 1024 * 1024);
  }
#else

#endif

  pcap_handle_ = handle;
  LOG_INFO("Capture initialized on interface: %s", cfg.interface.c_str());
  return true;
}

std::vector<std::pair<std::string, std::string>> LiveCapture::get_interfaces()
{
  std::vector<std::pair<std::string, std::string>> result;
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_if_t *devices = nullptr;
  if (pcap_findalldevs(&devices, errbuf) == -1)
  {
    LOG_ERROR("Failed to find devices: %s", errbuf);
    return result;
  }

  for (pcap_if_t *dev = devices; dev != nullptr; dev = dev->next)
  {
    std::string desc = dev->description ? dev->description : "Unknown";
    result.push_back({dev->name, desc});
  }

  pcap_freealldevs(devices);
  return result;
}

bool LiveCapture::start_capture(PacketCallback callback)
{
  if (!pcap_handle_)
  {
    LOG_ERROR("Capture not initialized");
    return false;
  }

  running_ = true;
  struct pcap_pkthdr *header = nullptr;
  const u_char *data = nullptr;
  int res;

  auto start_time = std::chrono::high_resolution_clock::now();

  while (running_ && (config_.packet_count == -1 ||
                      static_cast<int>(stats_.packets_captured) < config_.packet_count))
  {

    res = pcap_next_ex(static_cast<pcap_t *>(pcap_handle_), &header, &data);

    if (res == 0)
    {

      continue;
    }
    else if (res == -1)
    {
      LOG_ERROR("Capture error: %s", pcap_geterr(static_cast<pcap_t *>(pcap_handle_)));
      running_ = false;
      return false;
    }
    else if (res == -2)
    {

      break;
    }

    Packet pkt;
    pkt.raw_data.assign(data, data + header->caplen);
    pkt.timestamp_us = (uint64_t)header->ts.tv_sec * 1000000 + header->ts.tv_usec;
    pkt.length = header->len;
    pkt.capture_length = header->caplen;

    stats_.packets_captured++;
    stats_.bytes_captured += header->caplen;

    try
    {
      callback(pkt);
    }
    catch (const std::exception &e)
    {
      LOG_ERROR("Callback exception: %s", e.what());
    }
  }

  auto end_time = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);

  LOG_INFO("Capture stopped. Packets: %llu, Duration: %lld seconds",
           stats_.packets_captured, duration.count());

  return true;
}

void LiveCapture::stop_capture()
{
  running_ = false;
}

LiveCapture::Stats LiveCapture::get_stats() const
{
  return stats_;
}