#ifndef ANOMALY_DETECTOR_H
#define ANOMALY_DETECTOR_H

#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <cmath>

class AnomalyDetector
{
public:
  enum AnomalyType
  {
    HIGH_ENTROPY,
    TRAFFIC_BURST,
    UNUSUAL_PORTS,
    FREQUENCY_ANOMALY,
    DOMAIN_REPUTATION,
    DATA_EXFILTRATION
  };

  struct Anomaly
  {
    AnomalyType type;
    std::string subject;
    double confidence;
    std::string reason;
  };

  struct Config
  {
    double entropy_threshold = 7.0;
    int burst_threshold_pps = 10000;
    int burst_window_sec = 5;
    int history_size = 1000;
    bool enable_ml = true;
  };

  AnomalyDetector(const Config &cfg = Config());
  ~AnomalyDetector() = default;

  std::vector<Anomaly> analyze_packet(
      const std::string &domain,
      uint64_t packet_size,
      uint16_t dst_port,
      uint64_t timestamp_us,
      const std::string &payload);

  static double calculate_entropy(const std::string &data);

  bool detect_burst(uint64_t timestamp_us);

  bool is_unusual_port(const std::string &domain, uint16_t port);

  struct Stats
  {
    uint64_t total_packets_analyzed = 0;
    uint64_t anomalies_detected = 0;
    double avg_entropy = 0.0;
    int current_pps = 0;
  };
  Stats get_stats() const;

  void reset();

private:
  Config config_;
  Stats stats_;

  std::vector<uint64_t> packet_timestamps_;
  std::unordered_map<std::string, std::vector<uint16_t>> domain_ports_;
  std::unordered_map<std::string, double> domain_avg_entropy_;

  double calculate_frequency_score(const std::string &subject);
  double calculate_entropy_score(double entropy);
  double calculate_burst_score(int current_pps);
};

#endif