#pragma once

#include "types.h"
#include <vector>
#include <list>
#include <cstdint>

// Slotted timer wheel for O(1) flow expiration.
class TimerWheel {
public:
    TimerWheel(uint32_t capacity_sec) : buckets_(capacity_sec) {}

    // Schedule or reschedule a flow for expiration
    void schedule(const FiveTuple& key, uint32_t expiry_time) {
        uint32_t slot = expiry_time % buckets_.size();
        buckets_[slot].push_back(key);
    }

    // Get flows that might have expired at the given time
    std::list<FiveTuple> extractExpired(uint32_t current_time) {
        uint32_t slot = current_time % buckets_.size();
        std::list<FiveTuple> expired;
        expired.swap(buckets_[slot]);
        return expired;
    }

private:
    std::vector<std::list<FiveTuple>> buckets_;
};
