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

  class BatchDispatcher
  {
  public:
    static constexpr int BATCH_SIZE = 64;

    BatchDispatcher(ThreadPool &pool, PacketPool<> &pkt_pool, output::StatsTracker &stats)
        : pool_(pool), pkt_pool_(pkt_pool), stats_(stats) {}

    void submit(core::Packet *pkt)
    {
      batch_[count_++] = pkt;
      if (count_ == BATCH_SIZE)
      {
        flush();
      }
    }

    void flush()
    {
      if (count_ == 0)
        return;

      auto batch = std::vector<core::Packet *>(
          batch_.begin(), batch_.begin() + count_);
      count_ = 0;

      pool_.enqueue([b = std::move(batch), &pp = pkt_pool_, &st = stats_]()
                    {
            for (auto* pkt : b) {
                auto t0 = std::chrono::high_resolution_clock::now();
                auto t1 = std::chrono::high_resolution_clock::now();
                uint64_t us = std::chrono::duration_cast<std::chrono::microseconds>(
                    t1 - t0).count();
                
                st.record_packet(us);
                pp.release(pkt);
            } });
    }

  private:
    ThreadPool &pool_;
    PacketPool<> &pkt_pool_;
    output::StatsTracker &stats_;
    std::array<core::Packet *, BATCH_SIZE> batch_;
    int count_ = 0;
  };

}