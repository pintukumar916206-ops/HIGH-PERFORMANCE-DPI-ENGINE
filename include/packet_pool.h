#pragma once

#include "types.h"
#include <vector>
#include <atomic>
#include "compat.h"

//  PacketPool - Pre-allocated memory reservoir for high-speed data-path
// -------------------------------------------------------------
//  Simulates Hugepages by allocating a large contiguous slab
//  at startup. Eliminates malloc/free overhead in the fast-path.
//  Enables direct buffer access without copying from the reader.
// -------------------------------------------------------------
class PacketPool {
public:
    static constexpr uint32_t POOL_SIZE = 16384; // 128k packets
    static constexpr size_t PACKET_MAX_LEN  = 2048;   // Standard MTU+
    
    static PacketPool& instance() {
        static PacketPool pool;
        return pool;
    }

    // Leases a buffer from the pool. Returns nullptr if exhausted.
    RawPacket lease();

    // Returns a buffer to the pool for reuse.
    void release(RawPacket& pkt);

    size_t available() const noexcept { return available_count_.load(); }

private:
    PacketPool();
    ~PacketPool();

    uint8_t* slab_ = nullptr;
    std::vector<uint32_t> free_indices_;
    mutable compat::mutex stack_mu_;
    std::atomic<size_t> available_count_{0};

    // Prevent copies
    PacketPool(const PacketPool&) = delete;
    PacketPool& operator=(const PacketPool&) = delete;
};
