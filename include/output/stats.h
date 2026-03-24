#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <chrono>
#include "compat.h"
#include "core/packet.h"

namespace packet_analyzer::output
{

    // High-resolution metrics: sliding 10-second window + P99 latency histogram
    // Per-packet recording cost: two array increments (no mutex)
    class StatsTracker
    {
    public:
        static constexpr int WINDOW_S = 10;      // rolling 10-second window
        static constexpr int LAT_BUCKETS = 1000; // 1µs resolution: 0..999µs

        // Record packet: called after processing completes
        // latency_us: time from acquire to complete
        void record_packet(uint64_t latency_us)
        {
            auto now_s = now_seconds();

            // Advance window if we've crossed into a new second
            {
                compat::lock_guard<compat::mutex> lock(window_lock_);
                if (now_s != cur_sec_)
                {
                    advance_window(now_s);
                }
                window_[cur_slot_].store(window_[cur_slot_].load(std::memory_order_relaxed) + 1,
                                         std::memory_order_relaxed);
            }

            // Bucket latency histogram (no lock needed — atomic array)
            uint64_t b = std::min(latency_us, (uint64_t)(LAT_BUCKETS - 1));
            hist_[b].fetch_add(1, std::memory_order_relaxed);
            total_samples_.fetch_add(1, std::memory_order_relaxed);
        }

        // Overload for backward compatibility with Packet argument
        void record_packet(const core::Packet &packet)
        {
            record_packet(packet.get_processing_duration_us());
        }

        // Drop: packet discarded (backpressure or error)
        void record_drop()
        {
            dropped_.fetch_add(1, std::memory_order_relaxed);
        }

        // Average PPS over rolling 10-second window
        double get_sliding_pps() const
        {
            uint64_t sum = 0;
            for (const auto &slot : window_)
            {
                sum += slot.load(std::memory_order_relaxed);
            }
            return (double)sum / WINDOW_S;
        }

        // 99th percentile latency via histogram scan
        uint64_t get_p99_latency_us() const
        {
            uint64_t total = total_samples_.load(std::memory_order_relaxed);
            if (total == 0)
                return 0;

            uint64_t threshold = (total * 99) / 100;
            uint64_t cumulative = 0;
            for (int i = 0; i < LAT_BUCKETS; ++i)
            {
                cumulative += hist_[i].load(std::memory_order_relaxed);
                if (cumulative >= threshold)
                    return i;
            }
            return LAT_BUCKETS - 1;
        }

        // P50 (median)
        uint64_t get_p50_latency_us() const
        {
            uint64_t total = total_samples_.load(std::memory_order_relaxed);
            if (total == 0)
                return 0;

            uint64_t threshold = total / 2;
            uint64_t cumulative = 0;
            for (int i = 0; i < LAT_BUCKETS; ++i)
            {
                cumulative += hist_[i].load(std::memory_order_relaxed);
                if (cumulative >= threshold)
                    return i;
            }
            return LAT_BUCKETS - 1;
        }

        // Total packets processed (not dropped)
        uint64_t get_total_packets() const
        {
            return total_samples_.load(std::memory_order_relaxed);
        }

        // Total bytes (must be tracked separately during processing)
        void record_bytes(uint32_t len)
        {
            total_bytes_.fetch_add(len, std::memory_order_relaxed);
        }

        uint64_t get_total_bytes() const
        {
            return total_bytes_.load(std::memory_order_relaxed);
        }

        uint64_t get_dropped() const
        {
            return dropped_.load(std::memory_order_relaxed);
        }

        // Snapshot for display (backward compat struct)
        struct MetricsSnapshot
        {
            uint64_t total_packets;
            uint64_t total_bytes;
            uint64_t dropped_packets;
            double pps;
            double avg_latency_ms;
            double drop_rate_pct;
        };

        MetricsSnapshot get_snapshot() const
        {
            uint64_t tp = get_total_packets();
            uint64_t tb = get_total_bytes();
            uint64_t dr = get_dropped();
            double pps_val = get_sliding_pps();

            MetricsSnapshot s;
            s.total_packets = tp;
            s.total_bytes = tb;
            s.dropped_packets = dr;
            s.pps = pps_val;
            s.avg_latency_ms = (double)get_p50_latency_us() / 1000.0;
            s.drop_rate_pct = (tp + dr > 0) ? (100.0 * dr) / (tp + dr) : 0.0;
            return s;
        }

    private:
        // Circular 10-second window buffer
        std::array<std::atomic<uint64_t>, WINDOW_S> window_{};

        // Latency histogram: 1µs buckets, 0..999µs
        std::array<std::atomic<uint64_t>, LAT_BUCKETS> hist_{};

        // Counters
        std::atomic<uint64_t> total_samples_{0};
        std::atomic<uint64_t> total_bytes_{0};
        std::atomic<uint64_t> dropped_{0};

        // Window state
        int cur_slot_ = 0;
        int64_t cur_sec_ = 0;
        mutable compat::mutex window_lock_;

        int64_t now_seconds() const
        {
            auto now = std::chrono::steady_clock::now();
            return std::chrono::duration_cast<std::chrono::seconds>(
                       now.time_since_epoch())
                .count();
        }

        void advance_window(int64_t new_sec)
        {
            int64_t delta = std::min(new_sec - cur_sec_, (int64_t)WINDOW_S);
            for (int64_t i = 0; i < delta; ++i)
            {
                cur_slot_ = (cur_slot_ + 1) % WINDOW_S;
                window_[cur_slot_].store(0, std::memory_order_relaxed); // zero out reused slot
            }
            cur_sec_ = new_sec;
        }
    };

} // namespace packet_analyzer::output
