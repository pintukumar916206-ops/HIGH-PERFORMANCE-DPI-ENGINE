#include "sni_extractor.h"
#include <cstring>
#include <algorithm>
#include <cctype>

// TLS SNI Extractor
compat::optional<std::string> SNIExtractor::extract(const uint8_t* p,
                                                  size_t         len) {
    // Minimum bytes needed for a TLS Client Hello header:
    //   5 (TLS record) + 4 (handshake) + 2 (version) + 32 (random) + 1 (sesid len)
    constexpr size_t MIN_LEN = 44;
    if (!p || len < MIN_LEN) return compat::nullopt;

    // TLS Record Layer
    if (p[0] != 0x16) return compat::nullopt;  // Content-Type: Handshake
    // p[1..2] = legacy record revision/id — we accept any (0x0301, 0x0303…)
    // p[3..4] = record length

    // Handshake Protocol
    if (p[5] != 0x01) return compat::nullopt;  // Handshake-Type: ClientHello
    // p[6..8] = 3-byte handshake length

    // ClientHello body starts at offset 9
    // p[9..10]  = client_protocol_rev
    // p[11..42] = Random (32 bytes)
    size_t offset = 43;

    // Session ID
    if (offset >= len) return compat::nullopt;
    uint8_t sess_len = p[offset++];
    if (offset + sess_len > len) return compat::nullopt;
    offset += sess_len;

    // Cipher Suites
    if (offset + 2 > len) return compat::nullopt;
    uint16_t cs_len = r16(p + offset);  offset += 2;
    if (offset + cs_len > len) return compat::nullopt;
    offset += cs_len;

    // Compression Methods
    if (offset + 1 > len) return compat::nullopt;
    uint8_t comp_len = p[offset++];
    if (offset + comp_len > len) return compat::nullopt;
    offset += comp_len;

    // Extensions Length
    if (offset + 2 > len) return compat::nullopt;
    uint16_t ext_total = r16(p + offset);  offset += 2;
    size_t ext_end = offset + ext_total;
    if (ext_end > len) ext_end = len;  // clamp — don't trust the length field

    // Walk every extension until we find type 0x0000 (SNI)
    while (offset + 4 <= ext_end) {
        uint16_t ext_type = r16(p + offset);      offset += 2;
        uint16_t ext_dlen = r16(p + offset);      offset += 2;

        if (offset + ext_dlen > ext_end) break;   // truncated extension

        if (ext_type == 0x0000) {
            // SNI extension layout:
            //   2 bytes: SNI list length
            //   1 byte : SNI type (0x00 = host_name)
            //   2 bytes: SNI name length
            //   N bytes: SNI hostname (ASCII, no null terminator)
            if (ext_dlen < 5) return compat::nullopt;
            // uint16_t sni_list_len = r16(p + offset);  // not needed
            uint8_t  sni_type = p[offset + 2];
            if (sni_type != 0x00) return compat::nullopt;
            uint16_t sni_name_len = r16(p + offset + 3);
            if (5 + sni_name_len > ext_dlen) return compat::nullopt;
            // Construct and return the hostname string
            return std::string(reinterpret_cast<const char*>(p + offset + 5),
                               sni_name_len);
        }
        offset += ext_dlen;
    }
    return compat::nullopt;
}

// HTTP Host Extractor
compat::optional<std::string> HTTPHostExtractor::extract(const uint8_t* p,
                                                       size_t         len) {
    if (!p || len < 16) return compat::nullopt;

    // Quick first-byte check — all HTTP methods start with a capital letter
    if (p[0] < 'A' || p[0] > 'Z') return compat::nullopt;

    static const char* methods[] = {
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", nullptr
    };
    bool is_http = false;
    for (int i = 0; methods[i]; ++i) {
        size_t mlen = strlen(methods[i]);
        if (len >= mlen &&
            memcmp(p, methods[i], mlen) == 0) {
            is_http = true;
            break;
        }
    }
    if (!is_http) return compat::nullopt;

    // Scan for "Host:" header (case-insensitive)
    // We convert the payload to a string view and search for it.
    compat::string_view text(reinterpret_cast<const char*>(p),
                          std::min(len, size_t(4096)));

    // Try both capitalizations that are common in the wild
    size_t pos = text.find("\r\nHost: ");
    if (pos == compat::string_view::npos) pos = text.find("\r\nhost: ");
    if (pos == compat::string_view::npos) pos = text.find("\r\nHOST: ");
    if (pos == compat::string_view::npos) return compat::nullopt;

    pos += 8;  // skip "\r\nHost: "
    size_t end = text.find('\r', pos);
    if (end == compat::string_view::npos) end = text.find('\n', pos);
    if (end == compat::string_view::npos) end = text.size();

    auto sub = text.substr(pos, end - pos);
    std::string host(sub.data(), sub.size());
    // Strip port number if present (e.g. "example.com:8080" → "example.com")
    size_t colon = host.rfind(':');
    if (colon != std::string::npos) {
        bool all_digits = true;
        for (size_t i = colon + 1; i < host.size(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(host[i]))) {
                all_digits = false; break;
            }
        }
        if (all_digits) host.erase(colon);
    }
    if (host.empty()) return compat::nullopt;
    return compat::optional<std::string>(host);
}

// BitTorrent Detection
bool BitTorrentDetector::detect(const uint8_t* p, size_t len) {
    static const uint8_t BT_HANDSHAKE[] = {
        0x13, 'B','i','t','T','o','r','r','e','n','t',' ',
              'p','r','o','t','o','c','o','l'
    };
    if (!p || len < sizeof(BT_HANDSHAKE)) return false;
    return memcmp(p, BT_HANDSHAKE, sizeof(BT_HANDSHAKE)) == 0;
}
