#include "types.h"
#include "compat.h"
#include "packet_parser.h"
#include "sni_extractor.h"
#include "flow_tracker.h"
#include "rule_engine.h"
#include "bounded_queue.h"

#include <cassert>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <vector>
#include <atomic>
#include <chrono>

static int  g_tests_run    = 0;
static int  g_tests_passed = 0;
static int  g_tests_failed = 0;

#define CHECK(cond)                                                         \
    do {                                                                    \
        ++g_tests_run;                                                      \
        if (cond) {                                                         \
            ++g_tests_passed;                                               \
        } else {                                                            \
            ++g_tests_failed;                                               \
            std::cerr << "  FAIL  " << __FILE__ << ":" << __LINE__         \
                      << "  " << #cond << "\n";                            \
        }                                                                   \
    } while(0)

#define SECTION(name) std::cout << "\n[TEST] " << (name) << "\n"

static RawPacket buildTCPPacket(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
    static std::vector<uint8_t> buffer;
    buffer.assign(54, 0); 
    uint8_t* d = buffer.data();
    d[12]=0x08; d[13]=0x00; d[14]=0x45; d[23]=6;
    auto w32 = [&](int o, uint32_t v){ d[o]=(v>>24)&0xFF; d[o+1]=(v>>16)&0xFF; d[o+2]=(v>>8)&0xFF; d[o+3]=v&0xFF; };
    auto w16 = [&](int o, uint16_t v){ d[o]=(v>>8)&0xFF; d[o+1]=v&0xFF; };
    w32(26, src_ip); w32(30, dst_ip); w16(34, src_port); w16(36, dst_port);
    
    RawPacket pkt; 
    pkt.data = d;
    pkt.len = 54;
    pkt.ts_sec = 1000; pkt.orig_len = 54; 
    return pkt;
}

void test_packet_parser() {
    SECTION("PacketParser");
    auto raw = buildTCPPacket(0xC0A80101, 0xC0A80102, 50000, 443);
    ParsedPacket pkt;
    CHECK(PacketParser::parse(raw, pkt));
    CHECK(pkt.src_ip == 0xC0A80101);
}

void test_bounded_queue() {
    SECTION("BoundedQueue");
    BoundedQueue<int> q(2);
    q.push(1);
    auto v = q.pop();
    CHECK(v && *v == 1);
}

void test_concurrent_queue() {
    SECTION("BoundedQueue: Concurrent");
    BoundedQueue<int> q(10);
    std::atomic<int> sum{0};
    
    compat::thread t1([&]{
        for(int i=0; i<100; ++i) q.push(1);
    });
    
    compat::thread t2([&]{
        for(int i=0; i<100; ++i) {
            auto v = q.pop();
            if(v) sum.fetch_add(1);
        }
    });

    t1.join();
    q.shutdown();
    t2.join();
    CHECK(sum.load() == 100);
}

int main() {
    std::cout << "DPI Suite Starting (Win32 Compat)...\n";
    test_packet_parser();
    test_bounded_queue();
    test_concurrent_queue();
    std::cout << "\nResults: " << g_tests_passed << "/" << g_tests_run << " passed\n";
    return g_tests_failed == 0 ? 0 : 1;
}
