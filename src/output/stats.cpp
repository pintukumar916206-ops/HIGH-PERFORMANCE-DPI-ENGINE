#include "output/stats.h"

namespace packet_analyzer::output
{

    void StatsTracker::record_packet(const core::Packet &packet)
    {
        packet_count_++;
        byte_count_ += packet.raw().data.size();

        uint64_t latency_us = packet.get_processing_duration_us();
        total_latency_us_ += latency_us;
    }

    MetricsSnapshot StatsTracker::get_snapshot()
    {
        auto now = std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - start_time_).count();

        uint64_t packets = packet_count_.load();
        uint64_t drops = dropped_count_.load();
        uint64_t bytes = byte_count_.load();
        uint64_t latency_us = total_latency_us_.load();

        MetricsSnapshot snap;
        snap.total_packets = packets;
        snap.total_bytes = bytes;
        snap.dropped_packets = drops;
        snap.pps = duration > 0 ? static_cast<double>(packets) / duration : packets;
        snap.avg_latency_ms = packets > 0 ? (static_cast<double>(latency_us) / packets) / 1000.0 : 0.0;
        snap.drop_rate_pct = (packets + drops) > 0 ? (static_cast<double>(drops) / (packets + drops)) * 100.0 : 0.0;

        return snap;
    }

} // namespace packet_analyzer::output
