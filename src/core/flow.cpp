#include "core/flow.h"

namespace packet_analyzer {
namespace core {

void Flow::update(const Packet& packet) {
    if (packet_count_ == 0) {
        start_time_ = packet.raw().timestamp;
    }
    last_seen_ = packet.raw().timestamp;
    packet_count_++;
    byte_count_ += packet.raw().data.size();
}

} // namespace core
} // namespace packet_analyzer
