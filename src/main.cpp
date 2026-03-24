#include "dpi_pipeline.h"
#include <iostream>
#include <string>
#include <vector>

void printHelp() {
  std::cout << "HIGH-PERFORMANCE NETWORK PROCESSING ENGINE\n"
            << "Usage: packet_analyzer [options]\n\n"
            << "Options:\n"
            << "  --input <file>       Input PCAP file (required)\n"
            << "  --output <file>      Filtered PCAP output file\n"
            << "  --threads <N>        Number of worker threads (default: 4)\n"
            << "  --stats              Print real-time processing statistics\n"
            << "  --verbose            Print detailed per-packet logs (slow!)\n"
            << "  --block-ip <IP>      Block traffic to/from this IP or CIDR\n"
            << "  --block-domain <str> Block traffic containing this domain "
               "substring\n"
            << "  --block-app <app>    Block a specific application (YouTube, "
               "Facebook, etc.)\n"
            << "  --block-port <port>  Block a specific destination port\n"
            << "  --loop               Continuous looping (useful for performance monitoring)\n"
            << "  --delay <ms>         Delay between loops in milliseconds (default: 1000)\n"
            << "  --help               Display this help message\n\n"
            << "Example:\n"
            << "  packet_analyzer --input sample.pcap --threads 8 --block-app "
               "Netflix\n\n";
}

int main(int argc, char **argv) {
  if (argc < 2) {
    printHelp();
    return 1;
  }

  DpiPipeline::Config cfg;
  std::vector<std::string> block_ips;
  std::vector<std::string> block_domains;
  std::vector<std::string> block_apps;
  std::vector<uint16_t> block_ports;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--help") {
      printHelp();
      return 0;
    } else if (arg == "--input" && i + 1 < argc) {
      cfg.input_file = argv[++i];
    } else if (arg == "--output" && i + 1 < argc) {
      cfg.output_file = argv[++i];
    } else if (arg == "--threads" && i + 1 < argc) {
      cfg.num_workers = std::stoi(argv[++i]);
    } else if (arg == "--stats") {
      cfg.live_stats = true;
    } else if (arg == "--json") {
      cfg.json_output = true;
    } else if (arg == "--verbose") {
      cfg.verbose = true;
    } else if (arg == "--block-ip" && i + 1 < argc) {
      block_ips.push_back(argv[++i]);
    } else if (arg == "--block-domain" && i + 1 < argc) {
      block_domains.push_back(argv[++i]);
    } else if (arg == "--block-app" && i + 1 < argc) {
      block_apps.push_back(argv[++i]);
    } else if (arg == "--loop") {
      cfg.loop = true;
    } else if (arg == "--delay" && i + 1 < argc) {
      cfg.delay_ms = std::stoi(argv[++i]);
    } else if (arg == "--block-port" && i + 1 < argc) {
      block_ports.push_back(std::stoi(argv[++i]));
    }
  }

  if (cfg.input_file.empty()) {
    std::cerr << "Error: --input <file> is required.\n";
    return 1;
  }

  do {
    DpiPipeline pipeline(cfg);
    for (const auto &ip : block_ips)    pipeline.addBlockIP(ip);
    for (const auto &d : block_domains) pipeline.addBlockDomain(d);
    for (const auto &a : block_apps)    pipeline.addBlockApp(a);
    for (const auto &p : block_ports)   pipeline.addBlockPort(p);

    pipeline.run();
    if (cfg.json_output) {
      pipeline.printSummaryJson();
    } else {
      pipeline.printSummary();
    }
    if (cfg.loop) {
      std::cout << "\n[RESTARTING LOOP IN " << cfg.delay_ms << "ms...]\n";
      compat::sleep_ms(cfg.delay_ms);
    }
  } while (cfg.loop);

  return 0;
}
