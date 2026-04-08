#pragma once

#include "compat.h"
#include <cstdint>
#include <string>
#include <vector>

class SNIExtractor {
public:
    static compat::optional<std::string> extract(const uint8_t* payload,
                                               size_t         length);

private:
    static inline uint16_t r16(const uint8_t* p) noexcept {
        return (uint16_t(p[0]) << 8) | p[1];
    }
};

class HTTPHostExtractor {
public:
    static compat::optional<std::string> extract(const uint8_t* payload,
                                               size_t         length);
};

class BitTorrentDetector {
public:
    static bool detect(const uint8_t* payload, size_t length);
};
