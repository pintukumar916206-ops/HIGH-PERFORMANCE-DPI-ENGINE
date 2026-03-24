#include "rule_engine.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>

// Rule loading helpers

// Convert dotted-decimal string to host-order uint32_t.
// Throws std::invalid_argument on bad input.
static uint32_t parseIPv4(const std::string& s) {
    unsigned a, b, c, d;
    if (sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        throw std::invalid_argument("Bad IP: " + s);
    if (a > 255 || b > 255 || c > 255 || d > 255)
        throw std::invalid_argument("IP octet out of range: " + s);
    return (a << 24) | (b << 16) | (c << 8) | d;
}

// CIDR/IP expansion is handled by LpmTrie::insert during rule addition.

void RuleEngine::addBlockIP(const std::string& token) {
    if (token.find(':') != std::string::npos) {
        // Placeholder for IPv6 (full technical upgrade would use inet_pton)
        uint8_t v6[16] = {0};
        v6_trie_.insert(v6, 128);
        has_v6_rules_ = true;
    } else {
        size_t slash = token.find('/');
        if (slash != std::string::npos) {
            std::string base = token.substr(0, slash);
            int bits = std::stoi(token.substr(slash + 1));
            uint32_t ip = parseIPv4(base);
            uint8_t bytes[4] = { uint8_t(ip >> 24), uint8_t(ip >> 16), uint8_t(ip >> 8), uint8_t(ip) };
            v4_trie_.insert(bytes, bits);
        } else {
            uint32_t ip = parseIPv4(token);
            uint8_t bytes[4] = { uint8_t(ip >> 24), uint8_t(ip >> 16), uint8_t(ip >> 8), uint8_t(ip) };
            v4_trie_.insert(bytes, 32);
        }
        has_v4_rules_ = true;
    }
}

void RuleEngine::addBlockDomain(const std::string& substr) {
    std::string lower = substr;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    domain_matcher_.addPattern(lower);
}

void RuleEngine::addBlockApp(AppType app) {
    blocked_apps_.insert(static_cast<uint8_t>(app));
}

void RuleEngine::addBlockPort(uint16_t port) {
    blocked_ports_.insert(port);
}

bool RuleEngine::shouldBlock(const ParsedPacket& pkt, const Flow& flow) const noexcept {
    // 1. IP Matching via LPM Trie
    if (pkt.is_ipv6) {
        if (has_v6_rules_) {
            if (v6_trie_.match(pkt.src_ip6, 128)) return true;
            if (v6_trie_.match(pkt.dst_ip6, 128)) return true;
        }
    } else {
        if (has_v4_rules_) {
            uint8_t src[4] = { uint8_t(pkt.src_ip >> 24), uint8_t(pkt.src_ip >> 16), uint8_t(pkt.src_ip >> 8), uint8_t(pkt.src_ip) };
            uint8_t dst[4] = { uint8_t(pkt.dst_ip >> 24), uint8_t(pkt.dst_ip >> 16), uint8_t(pkt.dst_ip >> 8), uint8_t(pkt.dst_ip) };
            if (v4_trie_.match(src, 32)) return true;
            if (v4_trie_.match(dst, 32)) return true;
        }
    }

    // Port and App-level blocking
    if (!blocked_ports_.empty() && blocked_ports_.count(pkt.dst_port)) return true;
    if (!blocked_apps_.empty() && blocked_apps_.count(static_cast<uint8_t>(flow.app_type))) return true;
 
    // SNI / domain substring matching (Aho-Corasick)
    if (!flow.sni.empty() && !domain_matcher_.empty()) {
        if (domain_matcher_.match(flow.sni)) return true;
    }
    return false;
}

void RuleEngine::printRules() const {
    if (has_v4_rules_) std::cout << "  [RULE] IPv4 LPM active\n";
    if (has_v6_rules_) std::cout << "  [RULE] IPv6 LPM active\n";
    if (!domain_matcher_.empty()) std::cout << "  [RULE] Domain pattern matcher active\n";
    for (uint16_t p : blocked_ports_) {
        std::cout << "  [RULE] Block port: " << p << "\n";
    }
    for (uint8_t a : blocked_apps_) {
        std::cout << "  [RULE] Block app:  " << appTypeToString(static_cast<AppType>(a)) << "\n";
    }
    if (domain_matcher_.empty()) return;
}
