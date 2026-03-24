#pragma once

#include <cstdint>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace packet_analyzer::utils {

inline uint16_t net_to_host16(uint16_t v) { return ntohs(v); }
inline uint32_t net_to_host32(uint32_t v) { return ntohl(v); }
inline uint16_t host_to_net16(uint16_t v) { return htons(v); }
inline uint32_t host_to_net32(uint32_t v) { return htonl(v); }

} // namespace packet_analyzer::utils
