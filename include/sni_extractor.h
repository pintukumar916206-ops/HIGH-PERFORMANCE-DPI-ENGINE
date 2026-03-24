#pragma once

#include "compat.h"
#include <cstdint>
#include <string>
#include <vector>

// -------------------------------------------------------------
//  SNIExtractor - Extracts Server Name Indication from TLS ClientHello
// -------------------------------------------------------------
//  SNIExtractor  —  TLS Client Hello SNI extraction
//
//  Even though HTTPS traffic is encrypted, the TLS Client Hello
//  is sent in plaintext before the key exchange.  It contains
//  the Server Name Indication (SNI) extension (type 0x0000) which
//  carries the target hostname in cleartext.
// -------------------------------------------------------------
class SNIExtractor {
public:
    // Returns the SNI hostname string if found, compat::nullopt otherwise.
    static compat::optional<std::string> extract(const uint8_t* payload,
                                               size_t         length);

private:
    static inline uint16_t r16(const uint8_t* p) noexcept {
        return (uint16_t(p[0]) << 8) | p[1];
    }
};

// -------------------------------------------------------------
//  HTTPHostExtractor  —  HTTP/1.x plaintext Host: header
// -------------------------------------------------------------
class HTTPHostExtractor {
public:
    // Returns the Host header value if this looks like an HTTP request.
    static compat::optional<std::string> extract(const uint8_t* payload,
                                               size_t         length);
};

// -------------------------------------------------------------
//  BitTorrentDetector  —  handshake-based P2P detection
// -------------------------------------------------------------
class BitTorrentDetector {
public:
    static bool detect(const uint8_t* payload, size_t length);
};
