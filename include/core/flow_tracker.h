#pragma once

#include "flow.h"
#include <unordered_map>
#include <mutex>
#include <memory>
#include <array>

namespace packet_analyzer::core {

// Sharded FlowTracker with 32 independent buckets + locks
// Dramatically reduces mutex contention vs single global lock
class ShardedFlowTracker {
private:
    static constexpr size_t SHARD_COUNT = 32;
    static constexpr size_t SHARD_MASK = SHARD_COUNT - 1;  // For fast modulo bit operation

    struct Shard {
        std::unordered_map<FlowKey, std::shared_ptr<Flow>, FlowKeyHash> flows;
        mutable std::mutex lock;
    };

    std::array<Shard, SHARD_COUNT> shards_;

    size_t get_shard_index(const FlowKey& key) const {
        return key.compute_hash() & SHARD_MASK;
    }

public:
    static ShardedFlowTracker& instance() {
        static ShardedFlowTracker inst;
        return inst;
    }

    std::shared_ptr<Flow> get_or_create_flow(const FlowKey& key, const Packet& packet) {
        size_t shard_idx = get_shard_index(key);
        Shard& shard = shards_[shard_idx];
        
        std::lock_guard<std::mutex> lock(shard.lock);
        
        auto it = shard.flows.find(key);
        if (it == shard.flows.end()) {
            auto flow = std::make_shared<Flow>(key);
            flow->update(packet);
            shard.flows[key] = flow;
            return flow;
        }
        
        it->second->update(packet);
        return it->second;
    }

    size_t flow_count() const {
        size_t total = 0;
        for (const auto& shard : shards_) {
            std::lock_guard<std::mutex> lock(shard.lock);
            total += shard.flows.size();
        }
        return total;
    }

    std::vector<std::shared_ptr<Flow>> get_all_flows() const {
        std::vector<std::shared_ptr<Flow>> result;
        for (const auto& shard : shards_) {
            std::lock_guard<std::mutex> lock(shard.lock);
            for (const auto& pair : shard.flows) {
                result.push_back(pair.second);
            }
        }
        return result;
    }

    void clear() {
        for (auto& shard : shards_) {
            std::lock_guard<std::mutex> lock(shard.lock);
            shard.flows.clear();
        }
    }

private:
    ShardedFlowTracker() = default;
};

} // namespace packet_analyzer::core
