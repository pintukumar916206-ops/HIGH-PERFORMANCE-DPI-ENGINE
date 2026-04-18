#include <gtest/gtest.h>
#include "parser/parser.h"
#include "engine/engine.h"
#include "core/packet.h"

using namespace packet_analyzer;

TEST(ParserTest, EthernetParser) {
    core::RawPacket raw;

    raw.data = {
        0x00, 0x0c, 0x29, 0x4f, 0x8b, 0x35,
        0x00, 0x50, 0x56, 0xc0, 0x00, 0x08,
        0x08, 0x00,
        0x45, 0x00, 0x00, 0x3c,
        0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01,
        0x00, 0x50, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00
    };
    raw.timestamp = std::chrono::system_clock::now();
    
    core::Packet packet(std::move(raw));
    EXPECT_TRUE(parser::Parser::parse(packet));
    
    const auto& meta = packet.metadata();
    EXPECT_EQ(meta.src_ip, "127.0.0.1");
    EXPECT_EQ(meta.dst_ip, "127.0.0.1");
    EXPECT_EQ(meta.src_port, 80);
    EXPECT_EQ(meta.dst_port, 80);
    EXPECT_EQ(meta.protocol, 6);
}

TEST(DpiTest, HttpDetection) {
    core::RawPacket raw;
    raw.data.resize(60); 
    core::Packet packet(std::move(raw));
    
    auto& meta = packet.metadata();
    const char* http_payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    meta.payload = reinterpret_cast<const uint8_t*>(http_payload);
    meta.payload_len = strlen(http_payload);
    
    engine::DpiEngine::process(packet);
    EXPECT_EQ(meta.app_protocol, "HTTP");
    EXPECT_EQ(meta.http_host, "example.com");
}