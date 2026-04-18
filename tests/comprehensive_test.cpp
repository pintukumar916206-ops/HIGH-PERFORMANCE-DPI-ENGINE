#include <gtest/gtest.h>
#include "core/packet.h"
#include "parser/parser.h"
#include "engine/engine.h"
#include "output/stats.h"
#include "concurrency/bounded_queue.h"
#include <vector>

using namespace packet_analyzer;



TEST(ParserTest, ParseSimpleEthernet)
{

  std::vector<uint8_t> data(14);
  data[12] = 0x08;
  data[13] = 0x00;

  core::RawPacket raw;
  raw.data = data;
  raw.original_length = 14;
  raw.timestamp = std::chrono::system_clock::now();

  core::Packet packet(std::move(raw));
  bool result = parser::Parser::parse(packet);

  EXPECT_TRUE(result);
  EXPECT_EQ(packet.metadata().ether_type, 0x0800);
}

TEST(ParserTest, ParseIPv4Header)
{

  std::vector<uint8_t> data(34);


  data[12] = 0x08;
  data[13] = 0x00;


  data[14] = 0x45;
  data[19] = 6;


  data[26] = 192;
  data[27] = 168;
  data[28] = 1;
  data[29] = 1;
  data[30] = 192;
  data[31] = 168;
  data[32] = 1;
  data[33] = 2;

  core::RawPacket raw;
  raw.data = data;
  raw.original_length = data.size();
  raw.timestamp = std::chrono::system_clock::now();

  core::Packet packet(std::move(raw));
  bool result = parser::Parser::parse(packet);

  EXPECT_TRUE(result);
  EXPECT_TRUE(packet.metadata().has_ip);
  EXPECT_EQ(packet.metadata().ip_version, 4);
  EXPECT_EQ(packet.metadata().protocol, 6);
}

TEST(ParserTest, ParseTCPPort)
{

  std::vector<uint8_t> data(54);


  data[12] = 0x08;
  data[13] = 0x00;


  data[14] = 0x45;
  data[19] = 6;
  data[26] = 192;
  data[27] = 168;
  data[28] = 1;
  data[29] = 1;
  data[30] = 192;
  data[31] = 168;
  data[32] = 1;
  data[33] = 2;


  data[34] = 0x00;
  data[35] = 0x50;
  data[36] = 0x27;
  data[37] = 0x10;

  core::RawPacket raw;
  raw.data = data;
  raw.original_length = data.size();
  raw.timestamp = std::chrono::system_clock::now();

  core::Packet packet(std::move(raw));
  bool result = parser::Parser::parse(packet);

  EXPECT_TRUE(result);
  EXPECT_TRUE(packet.metadata().has_transport);
  EXPECT_EQ(packet.metadata().src_port, 80);
  EXPECT_EQ(packet.metadata().dst_port, 10000);
}



TEST(DpiEngineTest, DetectHTTP)
{
  core::RawPacket raw;
  raw.data = std::vector<uint8_t>(100);
  raw.original_length = 100;
  raw.timestamp = std::chrono::system_clock::now();

  core::Packet packet(std::move(raw));


  std::string http_request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
  packet.metadata().payload = reinterpret_cast<const uint8_t *>(http_request.c_str());
  packet.metadata().payload_len = http_request.size();
  packet.metadata().dst_port = 80;

  engine::DpiEngine::process(packet);

  EXPECT_EQ(packet.metadata().app_protocol, "HTTP");
  EXPECT_EQ(packet.metadata().http_host, "example.com");
}

TEST(DpiEngineTest, DetectDNS)
{
  core::RawPacket raw;
  raw.data = std::vector<uint8_t>(100);
  raw.original_length = 100;
  raw.timestamp = std::chrono::system_clock::now();

  core::Packet packet(std::move(raw));
  packet.metadata().dst_port = 53;
  packet.metadata().payload_len = 50;
  packet.metadata().payload = raw.data.data();

  engine::DpiEngine::process(packet);

  EXPECT_EQ(packet.metadata().app_protocol, "DNS");
}

TEST(DpiEngineTest, DetectTLS)
{
  core::RawPacket raw;

  std::vector<uint8_t> tls_data = {
      0x16,
      0x03, 0x01,
      0x00, 0x50
  };
  raw.data = tls_data;
  raw.original_length = tls_data.size();
  raw.timestamp = std::chrono::system_clock::now();

  core::Packet packet(std::move(raw));
  packet.metadata().payload = packet.raw().data.data();
  packet.metadata().payload_len = packet.raw().data.size();
  packet.metadata().dst_port = 443;

  engine::DpiEngine::process(packet);

  EXPECT_EQ(packet.metadata().app_protocol, "TLS");
}



TEST(StatsTest, RecordPacket)
{
  output::StatsTracker stats;

  core::RawPacket raw;
  raw.data = std::vector<uint8_t>(1000);
  raw.original_length = 1000;
  raw.timestamp = std::chrono::system_clock::now();

  core::Packet packet(std::move(raw));

  stats.record_packet(packet);

  auto snap = stats.get_snapshot();
  EXPECT_EQ(snap.total_packets, 1);
  EXPECT_EQ(snap.total_bytes, 1000);
  EXPECT_GT(snap.avg_latency_ms, 0);
}

TEST(StatsTest, DropTracking)
{
  output::StatsTracker stats;

  stats.record_drop();
  stats.record_drop();

  auto snap = stats.get_snapshot();
  EXPECT_EQ(snap.dropped_packets, 2);
}



TEST(BoundedQueueTest, PushPop)
{
  concurrency::BoundedQueue<int> queue(10);

  EXPECT_TRUE(queue.push(42));
  auto val = queue.pop();
  EXPECT_TRUE(val.has_value());
  EXPECT_EQ(val.value(), 42);
}

TEST(BoundedQueueTest, DropOnFull)
{
  concurrency::BoundedQueue<int> queue(2);

  EXPECT_TRUE(queue.push(1));
  EXPECT_TRUE(queue.push(2));
  EXPECT_FALSE(queue.push(3));

  EXPECT_EQ(queue.dropped_count(), 1);
}

TEST(BoundedQueueTest, StopSignal)
{
  concurrency::BoundedQueue<int> queue(10);
  queue.push(1);
  queue.stop();

  auto val = queue.pop();
  EXPECT_TRUE(val.has_value());
  EXPECT_EQ(val.value(), 1);

  val = queue.pop();
  EXPECT_FALSE(val.has_value());
}



TEST(ParserTest, EmptyPacket)
{
  std::vector<uint8_t> data(0);
  core::RawPacket raw;
  raw.data = data;
  raw.original_length = 0;
  raw.timestamp = std::chrono::system_clock::now();

  core::Packet packet(std::move(raw));
  bool result = parser::Parser::parse(packet);

  EXPECT_FALSE(result);
}

TEST(ParserTest, TruncatedIPv4)
{

  std::vector<uint8_t> data(20);
  data[12] = 0x08;
  data[13] = 0x00;

  core::RawPacket raw;
  raw.data = data;
  raw.original_length = 20;
  raw.timestamp = std::chrono::system_clock::now();

  core::Packet packet(std::move(raw));
  bool result = parser::Parser::parse(packet);

  EXPECT_FALSE(result);
}



TEST(StressTest, ManyPackets)
{
  output::StatsTracker stats;


  for (int i = 0; i < 1000; ++i)
  {
    core::RawPacket raw;
    raw.data = std::vector<uint8_t>(512);
    raw.original_length = 512;
    raw.timestamp = std::chrono::system_clock::now();

    core::Packet packet(std::move(raw));
    stats.record_packet(packet);
  }

  auto snap = stats.get_snapshot();
  EXPECT_EQ(snap.total_packets, 1000);
  EXPECT_EQ(snap.total_bytes, 512000);
}

TEST(StressTest, BoundedQueueUnderLoad)
{
  concurrency::BoundedQueue<int> queue(100);
  int dropped = 0;


  for (int i = 0; i < 1000; ++i)
  {
    if (!queue.push(i))
    {
      dropped++;
    }
  }

  EXPECT_GT(dropped, 0);
  EXPECT_GE(queue.total_pushed(), 100);
}

int main(int argc, char **argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}