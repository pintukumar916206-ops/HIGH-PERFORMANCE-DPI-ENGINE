#include "dpi_pipeline.h"
#include "live_capture.h"
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include "utils/logger.h"

void printHelp()
{
  std::cout << "NETWORK TRAFFIC ANALYSIS ENGINE\n"
            << "Usage: traffic_engine [options]\n\n"
            << "Input Options (choose one):\n"
            << "  --input <file>       Input PCAP file\n"
            << "  --live <interface>   Live capture from network interface (e.g., eth0)\n"
            << "  --live-list          List available network interfaces\n"
            << "\n"
            << "Processing Options:\n"
            << "  --output <file>      Filtered PCAP output file\n"
            << "  --threads <N>        Number of worker threads (default: 4)\n"
            << "  --stats              Print real-time processing statistics\n"
            << "  --benchmark          Run 3 passes and print averaged throughput results\n"
            << "  --rules <file>       Load blocking rules from a JSON config file\n"
            << "  --verbose            Print detailed per-packet logs\n"
            << "  --json               Output summary as JSON\n"
            << "\n"
            << "Filtering Options:\n"
            << "  --block-ip <IP>      Block traffic to/from this IP or CIDR\n"
            << "  --block-domain <str> Block traffic matching this domain substring\n"
            << "  --block-app <app>    Block a specific application (youtube, netflix, etc.)\n"
            << "  --block-port <port>  Block a specific destination port\n"
            << "\n"
            << "Other Options:\n"
            << "  --loop               Continuous looping\n"
            << "  --delay <ms>         Delay between loops in ms (default: 1000)\n"
            << "  --help               Display this help message\n\n"
            << "Examples:\n"
            << "  traffic_engine --input capture.pcap --threads 4\n"
            << "  traffic_engine --live eth0 --stats --threads 4\n"
            << "  traffic_engine --live-list\n\n";
}

int main(int argc, char **argv)
{
  if (argc < 2)
  {
    printHelp();
    return 1;
  }

  DpiPipeline::Config cfg;
  std::vector<std::string> block_ips;
  std::vector<std::string> block_domains;
  std::vector<std::string> block_apps;
  std::vector<uint16_t> block_ports;

  std::string rules_file;
  std::string live_interface;
  bool benchmark_mode = false;
  bool list_interfaces = false;

  for (int i = 1; i < argc; ++i)
  {
    std::string arg = argv[i];
    if (arg == "--help")
    {
      printHelp();
      return 0;
    }
    else if (arg == "--live-list")
    {
      list_interfaces = true;
    }
    else if (arg == "--live" && i + 1 < argc)
    {
      live_interface = argv[++i];
    }
    else if (arg == "--input" && i + 1 < argc)
    {
      cfg.input_file = argv[++i];
    }
    else if (arg == "--output" && i + 1 < argc)
    {
      cfg.output_file = argv[++i];
    }
    else if (arg == "--threads" && i + 1 < argc)
    {
      try
      {
        cfg.num_workers = std::stoi(argv[++i]);
        if (cfg.num_workers < 1 || cfg.num_workers > 64)
        {
          LOG_ERROR("Error: --threads must be between 1 and 64.");
          return 1;
        }
      }
      catch (...)
      {
        LOG_ERROR("Error: --threads expects a numeric value.");
        return 1;
      }
    }
    else if (arg == "--stats")
    {
      cfg.live_stats = true;
    }
    else if (arg == "--json")
    {
      cfg.json_output = true;
    }
    else if (arg == "--verbose")
    {
      cfg.verbose = true;
    }
    else if (arg == "--benchmark")
    {
      benchmark_mode = true;
    }
    else if (arg == "--rules" && i + 1 < argc)
    {
      rules_file = argv[++i];
    }
    else if (arg == "--block-ip" && i + 1 < argc)
    {
      block_ips.push_back(argv[++i]);
    }
    else if (arg == "--block-domain" && i + 1 < argc)
    {
      block_domains.push_back(argv[++i]);
    }
    else if (arg == "--block-app" && i + 1 < argc)
    {
      block_apps.push_back(argv[++i]);
    }
    else if (arg == "--loop")
    {
      cfg.loop = true;
    }
    else if (arg == "--delay" && i + 1 < argc)
    {
      try
      {
        cfg.delay_ms = std::stoi(argv[++i]);
      }
      catch (...)
      {
        LOG_ERROR("Error: --delay expects a numeric value.");
        return 1;
      }
    }
    else if (arg == "--block-port" && i + 1 < argc)
    {
      try
      {
        int port = std::stoi(argv[++i]);
        if (port < 0 || port > 65535)
        {
          LOG_ERROR("Error: --block-port must be between 0 and 65535.");
          return 1;
        }
        block_ports.push_back(static_cast<uint16_t>(port));
      }
      catch (...)
      {
        LOG_ERROR("Error: --block-port expects a numeric value.");
        return 1;
      }
    }
  }

  if (list_interfaces)
  {
    std::cout << "Available network interfaces:\n";
    auto interfaces = LiveCapture::get_interfaces();
    if (interfaces.empty())
    {
      std::cout << "  No interfaces found.\n";
    }
    else
    {
      for (const auto &[name, desc] : interfaces)
      {
        std::cout << "  " << name << " - " << desc << "\n";
      }
    }
    return 0;
  }

  if (cfg.input_file.empty() && live_interface.empty())
  {
    LOG_ERROR("Error: Either --input <file> or --live <interface> is required.");
    return 1;
  }

  if (benchmark_mode)
  {
    const int PASSES = 3;
    double total_pps = 0, total_mbps = 0, total_us = 0;
    std::cout << "benchmark: Running " << PASSES << " passes on "
              << cfg.input_file << "  (" << cfg.num_workers << " threads)\n\n";
    for (int pass = 1; pass <= PASSES; ++pass)
    {
      DpiPipeline pipeline(cfg);
      if (!rules_file.empty())
        pipeline.loadRules(rules_file);
      for (const auto &ip : block_ips)
        pipeline.addBlockIP(ip);
      for (const auto &d : block_domains)
        pipeline.addBlockDomain(d);
      for (const auto &a : block_apps)
        pipeline.addBlockApp(a);
      for (const auto &p : block_ports)
        pipeline.addBlockPort(p);
      pipeline.run();
      const Stats &s = pipeline.stats();
      double pps = s.throughputPps(), mbps = s.throughputMBps(), us = s.avgLatencyUs();
      std::cout << "  Pass " << pass << ":  "
                << std::fixed << std::setprecision(0) << pps << " pps  /  "
                << std::setprecision(1) << mbps << " MB/s  /  "
                << std::setprecision(1) << us << " us avg latency\n";
      total_pps += pps;
      total_mbps += mbps;
      total_us += us;
    }
    std::cout << "\n  Averaged over " << PASSES << " passes:\n";
    std::cout << "    Throughput:  " << std::fixed << std::setprecision(0)
              << total_pps / PASSES << " pps  /  "
              << std::setprecision(1) << total_mbps / PASSES << " MB/s\n";
    std::cout << "    Avg Latency: " << total_us / PASSES << " us/pkt\n";
    std::cout << "    Threads:     " << cfg.num_workers << "\n";
    return 0;
  }

  if (!live_interface.empty())
  {
    LiveCapture::Config live_cfg;
    live_cfg.interface = live_interface;
    live_cfg.packet_count = -1;

    LiveCapture capturer;
    if (!capturer.init(live_cfg))
    {
      LOG_ERROR("Failed to initialize live capture on interface '%s'", live_interface.c_str());
      return 1;
    }

    std::cout << "live: Capturing on " << live_interface << " (" << cfg.num_workers << " threads)\n";
    std::cout << "live: Press Ctrl+C to stop.\n\n";

    DpiPipeline pipeline(cfg);
    if (!rules_file.empty())
      pipeline.loadRules(rules_file);
    for (const auto &ip : block_ips)
      pipeline.addBlockIP(ip);
    for (const auto &d : block_domains)
      pipeline.addBlockDomain(d);
    for (const auto &a : block_apps)
      pipeline.addBlockApp(a);
    for (const auto &p : block_ports)
      pipeline.addBlockPort(p);

    auto process_packet = [&pipeline](const Packet &pkt)
    {
      RawPacket raw;
      raw.data = pkt.raw_data.data();
      raw.len = pkt.capture_length;
      raw.ts_sec = pkt.timestamp_us / 1000000;
      raw.ts_usec = (pkt.timestamp_us % 1000000);

      pipeline.feedPacket(raw);
    };

    if (!capturer.start_capture(process_packet))
    {
      LOG_ERROR("Capture failed");
      return 1;
    }

    if (cfg.json_output)
    {
      pipeline.printSummaryJson();
    }
    else
    {
      pipeline.printSummary();
    }
    return 0;
  }

  do
  {
    DpiPipeline pipeline(cfg);
    if (!rules_file.empty())
      pipeline.loadRules(rules_file);
    for (const auto &ip : block_ips)
      pipeline.addBlockIP(ip);
    for (const auto &d : block_domains)
      pipeline.addBlockDomain(d);
    for (const auto &a : block_apps)
      pipeline.addBlockApp(a);
    for (const auto &p : block_ports)
      pipeline.addBlockPort(p);

    pipeline.run();
    if (cfg.json_output)
    {
      pipeline.printSummaryJson();
    }
    else
    {
      pipeline.printSummary();
    }
    if (cfg.loop)
    {
      std::cout << "\nrestarting loop in " << cfg.delay_ms << "ms...\n";
      compat::sleep_ms(cfg.delay_ms);
    }
  } while (cfg.loop);

  return 0;
}