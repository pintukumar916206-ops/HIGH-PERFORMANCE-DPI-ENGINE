#pragma once

#include "core/packet.h"
#include <array>
#include <atomic>
#include <cstring>

namespace packet_analyzer::concurrency
{

  template <std::size_t POOL_SIZE = 2048>
  class PacketPool
  {
  public:
    PacketPool()
    {
      for (std::size_t i = 0; i < POOL_SIZE; ++i)
        free_stack_[i].store(i, std::memory_order_relaxed);
      top_.store(POOL_SIZE, std::memory_order_relaxed);
    }

    core::Packet *acquire()
    {
      std::size_t t = top_.load(std::memory_order_acquire);
      while (t > 0)
      {
        if (top_.compare_exchange_weak(t, t - 1, std::memory_order_acq_rel))
        {
          std::size_t slot_idx =
              free_stack_[t - 1].load(std::memory_order_relaxed);
          return &pool_[slot_idx];
        }
      }
      return nullptr;
    }

    void release(core::Packet *p)
    {
      if (!p)
        return;

      std::size_t idx = p - pool_.data();
      if (idx >= POOL_SIZE)
        return;

      std::size_t t = top_.load(std::memory_order_acquire);
      free_stack_[t].store(idx, std::memory_order_relaxed);
      top_.fetch_add(1, std::memory_order_release);
    }

    std::size_t available() const
    {
      return top_.load(std::memory_order_relaxed);
    }

    void clear()
    {
      top_.store(POOL_SIZE, std::memory_order_relaxed);
    }

  private:
    std::array<core::Packet, POOL_SIZE> pool_;
    std::array<std::atomic<std::size_t>, POOL_SIZE> free_stack_;
    std::atomic<std::size_t> top_;
  };

} // namespace packet_analyzer::concurrency
