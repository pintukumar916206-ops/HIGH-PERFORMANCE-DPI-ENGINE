#pragma once

#include "types.h"
#include "timer_wheel.h"
#include <unordered_map>
#include <vector>
#include <memory>
#include <string>

class FlowTracker {
public:
    explicit FlowTracker(int worker_id = 0);

    Flow* update(const ParsedPacket& pkt);

    const Flow* lookup(const FiveTuple& key) const;

    size_t flowCount() const noexcept { return table_.size(); }

    void evictStale(uint32_t now_sec, uint32_t max_age_sec = 60);

    std::vector<Flow> snapshot() const;

    int workerId() const noexcept { return worker_id_; }

private:
    int worker_id_;
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> table_;
    TimerWheel wheel_{120};
};