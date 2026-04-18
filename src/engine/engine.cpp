#include "engine/engine.h"
#include <string_view>
#include <cstring>

namespace packet_analyzer::engine
{


  static bool buffer_starts_with(std::string_view buffer, const char *pattern)
  {
    size_t len = std::strlen(pattern);
    return buffer.size() >= len && std::memcmp(buffer.data(), pattern, len) == 0;
  }


  static size_t find_in_buffer(const uint8_t *haystack, size_t haystack_len,
                               const char *needle, size_t needle_len)
  {
    if (needle_len > haystack_len)
      return SIZE_MAX;

    for (size_t i = 0; i <= haystack_len - needle_len; i++)
    {
      if (std::memcmp(haystack + i, needle, needle_len) == 0)
      {
        return i;
      }
    }
    return SIZE_MAX;
  }


  static bool extract_tls_sni(const uint8_t *payload, size_t payload_len,
                              uint32_t &sni_offset, uint16_t &sni_len,
                              uint8_t *raw_packet, size_t packet_offset)
  {
    if (payload_len < 44)
      return false;

    size_t offset = 43;
    if (offset >= payload_len)
      return false;


    if (offset >= payload_len)
      return false;
    uint8_t session_id_len = payload[offset];
    offset += 1 + session_id_len;
    if (offset + 2 > payload_len)
      return false;


    uint16_t cipher_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2 + cipher_len;
    if (offset + 1 > payload_len)
      return false;


    uint8_t compression_len = payload[offset];
    offset += 1 + compression_len;
    if (offset + 2 > payload_len)
      return false;


    uint16_t ext_len = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    while (offset + 4 <= payload_len)
    {
      uint16_t ext_type = (payload[offset] << 8) | payload[offset + 1];
      uint16_t ext_data_len = (payload[offset + 2] << 8) | payload[offset + 3];
      offset += 4;

      if (ext_type == 0)
      {
        if (offset + 2 > payload_len)
          break;
        uint16_t list_len = (payload[offset] << 8) | payload[offset + 1];
        offset += 2;

        if (offset + 1 > payload_len)
          break;

        uint8_t name_type = payload[offset];
        offset += 1;

        if (offset + 2 > payload_len)
          break;
        uint16_t name_len = (payload[offset] << 8) | payload[offset + 1];
        offset += 2;

        if (offset + name_len > payload_len)
          break;


        sni_offset = packet_offset + offset;
        sni_len = name_len;
        return true;
      }

      offset += ext_data_len;
    }

    return false;
  }


  static bool extract_http_host(const uint8_t *payload, size_t payload_len,
                                uint32_t &host_offset, uint16_t &host_len,
                                uint8_t *raw_packet, size_t packet_offset)
  {


    size_t host_pos = find_in_buffer(payload, payload_len, "Host: ", 6);
    if (host_pos == SIZE_MAX)
      return false;

    host_pos += 6;
    if (host_pos >= payload_len)
      return false;


    size_t end = find_in_buffer(payload + host_pos, payload_len - host_pos, "\r\n", 2);
    if (end == SIZE_MAX)
    {
      end = payload_len - host_pos;
    }

    if (end == 0)
      return false;

    host_offset = packet_offset + host_pos;
    host_len = static_cast<uint16_t>(end);
    return true;
  }


  static bool validate_dns(const uint8_t *payload, size_t payload_len,
                           uint16_t &transaction_id, uint16_t &question_count, uint8_t &flags)
  {
    if (payload_len < 12)
      return false;


    transaction_id = (payload[0] << 8) | payload[1];


    flags = payload[2];
    uint8_t rcode = flags & 0x0F;


    question_count = (payload[4] << 8) | payload[5];



    return question_count > 0 || (flags & 0x80);
  }

  void DpiEngine::process(core::Packet &packet)
  {
    auto &meta = packet.metadata();

    if (meta.payload_len == 0)
      return;


    const uint8_t *raw_data = packet.raw().data.data();
    uint32_t payload_offset = meta.payload - raw_data;


    if (detect_tls(packet, payload_offset))
      return;
    if (detect_http(packet, payload_offset))
      return;
    if (detect_dns(packet, payload_offset))
      return;
    if (detect_quic(packet))
      return;
  }

  bool DpiEngine::detect_http(core::Packet &packet, uint32_t payload_offset)
  {
    auto &meta = packet.metadata();
    std::string_view buffer(reinterpret_cast<const char *>(meta.payload), meta.payload_len);


    if (buffer_starts_with(buffer, "GET ") ||
        buffer_starts_with(buffer, "POST") ||
        buffer_starts_with(buffer, "PUT ") ||
        buffer_starts_with(buffer, "HEAD") ||
        buffer_starts_with(buffer, "DELETE") ||
        buffer_starts_with(buffer, "HTTP/"))
    {

      meta.app_protocol = core::PacketMetadata::AppProtocol::HTTP;


      uint8_t *raw_packet = const_cast<uint8_t *>(packet.raw().data.data());
      extract_http_host(meta.payload, meta.payload_len,
                        meta.http_host_offset, meta.http_host_len,
                        raw_packet, payload_offset);

      return true;
    }
    return false;
  }

  bool DpiEngine::detect_tls(core::Packet &packet, uint32_t payload_offset)
  {
    auto &meta = packet.metadata();
    const uint8_t *data = meta.payload;

    if (meta.payload_len < 5)
      return false;


    if (data[0] == 0x16 && data[1] == 0x03 &&
        (data[2] == 0x01 || data[2] == 0x02 || data[2] == 0x03))
    {

      meta.app_protocol = core::PacketMetadata::AppProtocol::TLS;


      if (meta.payload_len > 9 && data[5] == 0x01)
      {
        size_t handshake_offset = 9;

        uint8_t *raw_packet = const_cast<uint8_t *>(packet.raw().data.data());
        extract_tls_sni(data + handshake_offset, meta.payload_len - handshake_offset,
                        meta.sni_offset, meta.sni_len,
                        raw_packet, payload_offset + handshake_offset);
      }
      return true;
    }
    return false;
  }

  bool DpiEngine::detect_dns(core::Packet &packet, uint32_t payload_offset)
  {
    auto &meta = packet.metadata();


    if (meta.src_port != 53 && meta.dst_port != 53)
    {
      return false;
    }


    uint16_t transaction_id, question_count;
    uint8_t flags;

    if (!validate_dns(meta.payload, meta.payload_len, transaction_id, question_count, flags))
    {
      return false;
    }


    meta.app_protocol = core::PacketMetadata::AppProtocol::DNS;
    meta.dns_transaction_id = transaction_id;
    meta.dns_question_count = question_count;
    meta.dns_flags = flags;

    return true;
  }

  bool DpiEngine::detect_quic(core::Packet &packet)
  {
    auto &meta = packet.metadata();
    const uint8_t *data = meta.payload;

    if (meta.payload_len < 5)
      return false;


    if ((data[0] & 0x80) && meta.dst_port == 443)
    {
      uint32_t version = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];


      if (version == 0x00000001 || version == 0x6b3343cf ||
          (version & 0xFF000000) == 0xFF000000)
      {
        meta.app_protocol = core::PacketMetadata::AppProtocol::QUIC;
        return true;
      }
    }
    return false;
  }

  bool RuleEngine::should_block(const core::Packet &packet) const
  {
    const auto &meta = packet.metadata();

    for (const auto &rule : rules_)
    {
      bool match = true;


      if (rule.ipv4_src != 0 && rule.ipv4_src != meta.src_ip_v4)
        match = false;
      if (rule.ipv4_dst != 0 && rule.ipv4_dst != meta.dst_ip_v4)
        match = false;

      if (rule.port != 0 &&
          (rule.port != meta.src_port && rule.port != meta.dst_port))
      {
        match = false;
      }

      if (rule.protocol != 0 && rule.protocol != meta.protocol)
        match = false;

      if (match && rule.block)
        return true;
    }
    return false;
  }

}