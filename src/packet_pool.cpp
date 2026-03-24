#include "packet_pool.h"
#include <cstdlib>
#include <algorithm>
#ifdef _WIN32
#include <malloc.h>
#endif

PacketPool::PacketPool() {
    // Allocate contiguous slab (approx 256MB for 128k packets)
    // alignas(4096) for page alignment
#ifdef _WIN32
    slab_ = static_cast<uint8_t*>(malloc(POOL_SIZE * PACKET_MAX_LEN));
#else
    posix_memalign((void**)&slab_, 4096, POOL_SIZE * PACKET_MAX_LEN);
#endif

    if (!slab_) return;

    free_indices_.reserve(POOL_SIZE);
    for (uint32_t i = 0; i < POOL_SIZE; ++i) {
        free_indices_.push_back(i);
    }
    available_count_.store(POOL_SIZE);
}

PacketPool::~PacketPool() {
#ifdef _WIN32
    free(slab_);
#else
    free(slab_);
#endif
}

RawPacket PacketPool::lease() {
    compat::lock_guard<compat::mutex> lock(stack_mu_);
    if (free_indices_.empty()) return {};

    uint32_t idx = free_indices_.back();
    free_indices_.pop_back();
    available_count_.fetch_sub(1);

    RawPacket pkt;
    pkt.data = slab_ + (static_cast<size_t>(idx) * PACKET_MAX_LEN);
    pkt.len  = 0;
    pkt._pool_ref = reinterpret_cast<void*>(static_cast<uintptr_t>(idx));
    return pkt;
}

void PacketPool::release(RawPacket& pkt) {
    if (!pkt.data || !pkt._pool_ref) return;

    uint32_t idx = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pkt._pool_ref));
    
    {
        compat::lock_guard<compat::mutex> lock(stack_mu_);
        free_indices_.push_back(idx);
    }
    
    available_count_.fetch_add(1);
    
    // Clear the packet to prevent double-release
    pkt.data = nullptr;
    pkt.len = 0;
    pkt._pool_ref = nullptr;
}
