#pragma once

#include "core/packet.h"
#include "thread_pool.h"
#include "packet_pool.h"
#include "../output/stats.h"
#include <array>
#include <vector>
#include <chrono>

namespace packet_analyzer::concurrency
{

  // Batch dispatcher: accumulates 64 packets then enqueues as one unit
  // Reduces mutex acquisitions from 80K/sec to ~1.3K/sec at 80K PPS
  // Usage:
  //   BatchDispatcher dispatcher(thread_pool, packet_pool, stats);
  //   for (each packet) {
  //       pool->release(packet);
  //       dispatcher.submit(packet);
  //   }
  //   dispatcher.flush();
  class BatchDispatcher
  {
  public:
    static constexpr int BATCH_SIZE = 64;

    BatchDispatcher(ThreadPool &pool, PacketPool<> &pkt_pool, output::StatsTracker &stats)
        : pool_(pool), pkt_pool_(pkt_pool), stats_(stats) {}

    // Submit packet to batch accumulator
    // Auto-flushes when batch reaches BATCH_SIZE
    void submit(core::Packet *pkt)
    {
      batch_[count_++] = pkt;
      if (count_ == BATCH_SIZE)
      {
        flush();
      }
    }

    // Flush partial batch at end of capture session
    void flush()
    {
      if (count_ == 0)
        return;

      // Move batch into a vector (stack-to-heap, single allocation)
      auto batch = std::vector<core::Packet *>(
          batch_.begin(), batch_.begin() + count_);
      count_ = 0;

      // ONE enqueue call for all 64 packets = ONE mutex acquisition
      pool_.enqueue([b = std::move(batch), &pp = pkt_pool_, &st = stats_]()
                    {
            for (auto* pkt : b) {
                // Measure latency inside worker
                auto t0 = std::chrono::high_resolution_clock::now();
                
                // [Process flow tracking would happen here]
                
                auto t1 = std::chrono::high_resolution_clock::now();
                uint64_t us = std::chrono::duration_cast<std::chrono::microseconds>(
                    t1 - t0).count();
                
                st.record_packet(us);
                pp.release(pkt); // return slot to pool
            } });
    }

  private:
    ThreadPool &pool_;
    PacketPool<> &pkt_pool_;
    output::StatsTracker &stats_;
    std::array<core::Packet *, BATCH_SIZE> batch_;
    int count_ = 0;
  };

} // namespace packet_analyzer::concurrency
