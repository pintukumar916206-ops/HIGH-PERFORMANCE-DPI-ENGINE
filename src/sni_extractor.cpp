#include "sni_extractor.h"
#include <cstring>
#include <algorithm>
#include <cctype>

compat::optional<std::string> SNIExtractor::extract(const uint8_t* p,
                                                  size_t         len) {
    constexpr size_t MIN_LEN = 44;
    if (!p || len < MIN_LEN) return compat::nullopt;

    if (p[0] != 0x16) return compat::nullopt;

    if (p[5] != 0x01) return compat::nullopt;

    size_t offset = 43;

    if (offset >= len) return compat::nullopt;
    uint8_t sess_len = p[offset++];
    if (offset + sess_len > len) return compat::nullopt;
    offset += sess_len;

    if (offset + 2 > len) return compat::nullopt;
    uint16_t cs_len = r16(p + offset);  offset += 2;
    if (offset + cs_len > len) return compat::nullopt;
    offset += cs_len;

    if (offset + 1 > len) return compat::nullopt;
    uint8_t comp_len = p[offset++];
    if (offset + comp_len > len) return compat::nullopt;
    offset += comp_len;

    if (offset + 2 > len) return compat::nullopt;
    uint16_t ext_total = r16(p + offset);  offset += 2;
    size_t ext_end = offset + ext_total;
    if (ext_end > len) ext_end = len;

    while (offset + 4 <= ext_end) {
        uint16_t ext_type = r16(p + offset);      offset += 2;
        uint16_t ext_dlen = r16(p + offset);      offset += 2;

        if (offset + ext_dlen > ext_end) break;

        if (ext_type == 0x0000) {
            if (ext_dlen < 5) return compat::nullopt;
            uint8_t  sni_type = p[offset + 2];
            if (sni_type != 0x00) return compat::nullopt;
            uint16_t sni_name_len = r16(p + offset + 3);
            if (5 + sni_name_len > ext_dlen) return compat::nullopt;
            return std::string(reinterpret_cast<const char*>(p + offset + 5),
                               sni_name_len);
        }
        offset += ext_dlen;
    }
    return compat::nullopt;
}

compat::optional<std::string> HTTPHostExtractor::extract(const uint8_t* p,
                                                       size_t         len) {
    if (!p || len < 16) return compat::nullopt;

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

    compat::string_view text(reinterpret_cast<const char*>(p),
                          std::min(len, size_t(4096)));

    size_t pos = text.find("\r\nHost: ");
    if (pos == compat::string_view::npos) pos = text.find("\r\nhost: ");
    if (pos == compat::string_view::npos) pos = text.find("\r\nHOST: ");
    if (pos == compat::string_view::npos) return compat::nullopt;

    pos += 8;
    size_t end = text.find('\r', pos);
    if (end == compat::string_view::npos) end = text.find('\n', pos);
    if (end == compat::string_view::npos) end = text.size();

    auto sub = text.substr(pos, end - pos);
    std::string host(sub.data(), sub.size());
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

bool BitTorrentDetector::detect(const uint8_t* p, size_t len) {
    static const uint8_t BT_HANDSHAKE[] = {
        0x13, 'B','i','t','T','o','r','r','e','n','t',' ',
              'p','r','o','t','o','c','o','l'
    };
    if (!p || len < sizeof(BT_HANDSHAKE)) return false;
    return memcmp(p, BT_HANDSHAKE, sizeof(BT_HANDSHAKE)) == 0;
}
