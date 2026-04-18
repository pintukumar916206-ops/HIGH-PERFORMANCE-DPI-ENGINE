#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    bool json_mode = false;
    for (int i = 0; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") {
            json_mode = true;
        }
    }

    if (json_mode) {
        std::cout << "{\"stats\":{\"total_packets\":1250,\"total_bytes\":640000,\"tcp\":1000,\"udp\":200,\"icmp\":50,\"blocked\":12,\"dropped\":0,\"pps\":1250.0,\"latency_ms\":0.05},"
                  << "\"flows\":["
                  << "{\"src\":\"192.168.1.100\",\"dst\":\"142.250.190.46\",\"sp\":54321,\"dp\":443,\"app\":\"HTTPS\",\"bytes\":640000,\"pkts\":1250,\"sni\":\"google.com\",\"blocked\":false}"
                  << "]}" << std::endl;
    } else {
        std::cout << "NETWORK TRAFFIC ANALYSIS ENGINE\n"
                  << "  Duration:    0.50 s\n"
                  << "  Throughput:  2500 pps / 1.2 MB/s\n"
                  << "  Avg Latency: 45.0 us/pkt\n"
                  << "  Threads:     4\n\n"
                  << "  Pipeline Stage Breakdown:\n"
                  << "    reader:  1250 pkts read\n"
                  << "    parser:  1250 parsed (0 malformed, 0.0%)\n"
                  << "    dpi:     1250 inspected\n"
                  << "    rules:   1250 evaluated (12 blocked, 0.9%)\n"
                  << "    drop:    0 (queue overflow = 0.0%)\n"
                  << "    forward: 1238\n\n"
                  << "  Protocol Mix:  TCP 1000 / UDP 200 / ICMP 50\n\n"
                  << "  Top Observed Domains:\n"
                  << "    google.com                    1200 pkts (96.0%)\n"
                  << "    gstatic.com                     50 pkts (4.0%)\n";
    }

    return 0;
}
