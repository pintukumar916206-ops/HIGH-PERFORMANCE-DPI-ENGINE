#include "anomaly_detector.h"
#include "utils/logger.h"
#include <cmath>
#include <algorithm>
#include <numeric>

AnomalyDetector::AnomalyDetector(const Config &cfg) : config_(cfg) {}

std::vector<AnomalyDetector::Anomaly> AnomalyDetector::analyze_packet(
    const std::string &domain,
    uint64_t packet_size,
    uint16_t dst_port,
    uint64_t timestamp_us,
    const std::string &payload)
{

  std::vector<Anomaly> anomalies;
  stats_.total_packets_analyzed++;

  if (!payload.empty())
  {
    double entropy = calculate_entropy(payload);
    domain_avg_entropy_[domain] =
        (domain_avg_entropy_[domain] * 0.9) + (entropy * 0.1);

    if (entropy > config_.entropy_threshold)
    {
      double confidence = std::min(1.0, entropy / 8.0);
      anomalies.push_back({HIGH_ENTROPY,
                           domain,
                           confidence,
                           "Entropy: " + std::to_string(entropy) + " (possible encryption/exfiltration)"});
      stats_.anomalies_detected++;
    }
  }

  packet_timestamps_.push_back(timestamp_us);
  if (packet_timestamps_.size() > 100)
  {
    packet_timestamps_.erase(packet_timestamps_.begin());
  }

  if (detect_burst(timestamp_us))
  {
    int pps = stats_.current_pps;
    double confidence = std::min(1.0, (double)pps / (config_.burst_threshold_pps * 2));
    anomalies.push_back({TRAFFIC_BURST,
                         domain,
                         confidence,
                         "Burst detected: " + std::to_string(pps) + " pps"});
    stats_.anomalies_detected++;
  }

  if (is_unusual_port(domain, dst_port))
  {
    domain_ports_[domain].push_back(dst_port);
    anomalies.push_back({UNUSUAL_PORTS,
                         domain + ":" + std::to_string(dst_port),
                         0.6,
                         "Unusual port for domain"});
    stats_.anomalies_detected++;
  }

  if (packet_size > 100000)
  {
    anomalies.push_back({DATA_EXFILTRATION,
                         domain,
                         0.75,
                         "Large packet detected: " + std::to_string(packet_size) + " bytes"});
    stats_.anomalies_detected++;
  }

  double freq_score = calculate_frequency_score(domain);
  if (freq_score > 0.8)
  {
    anomalies.push_back({FREQUENCY_ANOMALY,
                         domain,
                         freq_score,
                         "Unusual access frequency"});
    stats_.anomalies_detected++;
  }

  return anomalies;
}

double AnomalyDetector::calculate_entropy(const std::string &data)
{
  if (data.empty())
    return 0.0;

  int freq[256] = {0};
  for (unsigned char c : data)
  {
    freq[c]++;
  }

  double entropy = 0.0;
  double len = data.length();

  for (int f : freq)
  {
    if (f > 0)
    {
      double p = f / len;
      entropy -= p * std::log2(p);
    }
  }

  return entropy;
}

bool AnomalyDetector::detect_burst(uint64_t timestamp_us)
{
  if (packet_timestamps_.size() < 10)
    return false;

  uint64_t cutoff_time = timestamp_us - (config_.burst_window_sec * 1000000ULL);
  int packets_in_window = 0;

  for (uint64_t ts : packet_timestamps_)
  {
    if (ts > cutoff_time)
    {
      packets_in_window++;
    }
  }

  stats_.current_pps = (packets_in_window * 1000000) / (config_.burst_window_sec * 1000000);

  return stats_.current_pps > config_.burst_threshold_pps;
}

bool AnomalyDetector::is_unusual_port(const std::string &domain, uint16_t port)
{

  static const std::vector<uint16_t> COMMON_PORTS = {
      80, 443, 22, 25, 53, 110, 143, 3306, 5432, 27017, 6379, 8080, 8443};

  if (domain_ports_.find(domain) == domain_ports_.end())
  {
    return false;
  }

  if (std::find(COMMON_PORTS.begin(), COMMON_PORTS.end(), port) != COMMON_PORTS.end())
  {
    return false;
  }

  const auto &ports = domain_ports_[domain];
  if (std::find(ports.begin(), ports.end(), port) == ports.end())
  {

    return true;
  }

  return false;
}

AnomalyDetector::Stats AnomalyDetector::get_stats() const
{
  return stats_;
}

void AnomalyDetector::reset()
{
  packet_timestamps_.clear();
  domain_ports_.clear();
  domain_avg_entropy_.clear();
  stats_ = Stats();
}

double AnomalyDetector::calculate_frequency_score(const std::string &subject)
{
  if (packet_timestamps_.size() < 10)
    return 0.0;

  auto now = std::chrono::high_resolution_clock::now();
  auto window_start = now - std::chrono::seconds(5);

  uint64_t now_us = std::chrono::duration_cast<std::chrono::microseconds>(
                        now.time_since_epoch())
                        .count();
  uint64_t start_us = std::chrono::duration_cast<std::chrono::microseconds>(
                          window_start.time_since_epoch())
                          .count();

  uint64_t count = 0;
  for (auto ts : packet_timestamps_)
  {
    if (ts >= start_us)
      count++;
  }

  double current_rate = count / 5.0;

  uint64_t total = packet_timestamps_.size();
  double mean_rate = total / 60.0;

  if (mean_rate < 1.0)
    return 0.0;

  double variance = 0.0;
  for (auto ts : packet_timestamps_)
  {
    variance += (ts - mean_rate) * (ts - mean_rate);
  }
  variance /= total;

  double stddev = std::sqrt(variance);
  if (stddev < 0.1)
    stddev = 0.1;

  double z_score = (current_rate - mean_rate) / stddev;

  if (z_score < 2.0)
    return 0.0;

  double confidence = std::min(1.0, z_score / 5.0);
  return confidence;
}

double AnomalyDetector::calculate_entropy_score(double entropy)
{

  return std::min(1.0, entropy / 8.0);
}

double AnomalyDetector::calculate_burst_score(int current_pps)
{

  if (current_pps <= config_.burst_threshold_pps)
    return 0.0;

  double excess = (double)(current_pps - config_.burst_threshold_pps) /
                  config_.burst_threshold_pps;
  return std::min(1.0, excess * 0.5);
}