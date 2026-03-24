#pragma once

#include "core/packet.h"
#include <array>
#include <atomic>
#include <cstring>

namespace packet_analyzer::concurrency
{

  // Lock-free packet pool: pre-allocated slab, atomic acquire/release
  // Eliminates one malloc/free per packet at 80K PPS
  // Usage:
  //   Packet* p = pool.acquire();
  //   if (!p) drop_packet(); // backpressure
  //   process(p);
  //   pool.release(p);       // O(1) atomic push
  template <std::size_t POOL_SIZE = 2048>
  class PacketPool
  {
  public:
    PacketPool()
    {
      // Pre-fill free stack with slot indices [0, POOL_SIZE)
      for (std::size_t i = 0; i < POOL_SIZE; ++i)
        free_stack_[i].store(i, std::memory_order_relaxed);
      top_.store(POOL_SIZE, std::memory_order_relaxed);
    }

    // Acquire: atomic CAS pop from free stack
    // Returns nullptr if pool exhausted (backpressure signal — drop packet)
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
      return nullptr; // pool empty
    }

    // Release: return packet to pool via atomic push
    // The slot index is recovered by pointer arithmetic
    void release(core::Packet *p)
    {
      if (!p)
        return;

      // Recover slot index from pointer: (p - base) / stride
      std::size_t idx = p - pool_.data();
      if (idx >= POOL_SIZE)
        return; // safety check: not from this pool

      std::size_t t = top_.load(std::memory_order_acquire);
      free_stack_[t].store(idx, std::memory_order_relaxed);
      top_.fetch_add(1, std::memory_order_release);
    }

    // Query available slots
    std::size_t available() const
    {
      return top_.load(std::memory_order_relaxed);
    }

    // Reset pool (unsafe — use only at shutdown)
    void clear()
    {
      top_.store(POOL_SIZE, std::memory_order_relaxed);
    }

  private:
    std::array<core::Packet, POOL_SIZE> pool_;                   // one contiguous slab
    std::array<std::atomic<std::size_t>, POOL_SIZE> free_stack_; // available slot indices
    std::atomic<std::size_t> top_;                               // stack pointer
  };

} // namespace packet_analyzer::concurrency
