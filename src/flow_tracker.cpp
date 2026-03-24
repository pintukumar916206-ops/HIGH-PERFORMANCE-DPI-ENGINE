#include "flow_tracker.h"
#include <algorithm>

FlowTracker::FlowTracker(int worker_id) : worker_id_(worker_id) {

  table_.reserve(1 << 16);
}

Flow *FlowTracker::update(const ParsedPacket &pkt) {

  FiveTuple canon = pkt.tuple.canonical();

  std::pair<std::unordered_map<FiveTuple, Flow, FiveTupleHash>::iterator, bool>
      result = table_.emplace(canon, Flow{});
  auto it = result.first;
  bool inserted = result.second;
  Flow &flow = it->second;

  if (inserted) {
    flow.key = canon;
    flow.first_ts_sec = pkt.raw.ts_sec;
    flow.first_ts_usec = pkt.raw.ts_usec;
  }

  flow.pkt_count += 1;
  flow.byte_count += pkt.ip_total_len > 0 ? pkt.ip_total_len : 64u;
  flow.last_ts_sec = pkt.raw.ts_sec;
  flow.last_ts_usec = pkt.raw.ts_usec;

  auto is_generic = [](AppType t) {
    return t == AppType::UNKNOWN || t == AppType::HTTPS ||
           t == AppType::TLS_OTHER;
  };
  if (is_generic(flow.app_type) && !is_generic(pkt.app_type)) {
    flow.app_type = pkt.app_type;
  }

  if (!pkt.sni.empty() && !flow.sni_seen) {
    flow.sni = pkt.sni;
    flow.sni_seen = true;
    if (flow.app_type == AppType::UNKNOWN || flow.app_type == AppType::HTTPS ||
        flow.app_type == AppType::TLS_OTHER) {
      AppType from_sni = sniToAppType(pkt.sni);
      if (from_sni != AppType::UNKNOWN) {
        flow.app_type = from_sni;
      }
    }
  }

  wheel_.schedule(canon, pkt.raw.ts_sec + 120);

  return &flow;
}

const Flow *FlowTracker::lookup(const FiveTuple &key) const {
  auto it = table_.find(key.canonical());
  return it != table_.end() ? &it->second : nullptr;
}

void FlowTracker::evictStale(uint32_t now_sec, uint32_t max_age_sec) {
  auto expired = wheel_.extractExpired(now_sec);
  for (const auto &key : expired) {
    auto it = table_.find(key);
    if (it != table_.end()) {
      if (it->second.last_ts_sec + max_age_sec <= now_sec) {
        table_.erase(it);
      }
    }
  }
}

std::vector<Flow> FlowTracker::snapshot() const {
  std::vector<Flow> result;
  result.reserve(table_.size());
  for (auto it = table_.begin(); it != table_.end(); ++it) {
    result.push_back(it->second);
  }
  return result;
}
