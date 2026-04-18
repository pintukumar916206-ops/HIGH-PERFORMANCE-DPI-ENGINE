#pragma once

#include <vector>
#include <cstdint>

struct Packet
{
  std::vector<uint8_t> raw_data;
  uint64_t timestamp_us = 0;
  uint32_t length = 0;
  uint32_t capture_length = 0;
};
