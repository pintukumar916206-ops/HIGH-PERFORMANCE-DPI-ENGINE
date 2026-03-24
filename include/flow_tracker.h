#pragma once

#include "types.h"
#include "timer_wheel.h"
#include <unordered_map>
#include <vector>
#include <memory>
#include <string>

//  The table is an unordered_map keyed on the canonical FiveTuple
//  (lower-IP first).  This means a single Flow record covers both
//  directions of a bidirectional connection (e.g. client→server and
//  server→client are the same Flow).
// -------------------------------------------------------------
//  FlowTracker
// -------------------------------------------------------------
class FlowTracker {
public:
    explicit FlowTracker(int worker_id = 0);

    // Update (or create) the flow for this packet.  Returns a pointer to
    // the flow record — the caller may read/modify it in-place.
    // The pointer remains valid until the next call to update() or clear().
    Flow* update(const ParsedPacket& pkt);

    // Retrieve without modifying (returns nullptr if not found)
    const Flow* lookup(const FiveTuple& key) const;

    // Total number of distinct flows seen by this worker
    size_t flowCount() const noexcept { return table_.size(); }

    // Call periodically to free memory
    void evictStale(uint32_t now_sec, uint32_t max_age_sec = 60);

    // Snapshot for reporting
    std::vector<Flow> snapshot() const;

    int workerId() const noexcept { return worker_id_; }

private:
    int worker_id_;
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> table_;
    TimerWheel wheel_{120}; // Support up to 120s max age
};
