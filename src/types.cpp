#include "types.h"
#include <sstream>
#include <algorithm>
#include <cctype>

// -------------------------------------------------------------
//  IP address formatting
// -------------------------------------------------------------
std::string ipToString(const uint8_t* ip, bool is_ipv6) {
    if (!is_ipv6) {
        return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." +
               std::to_string(ip[2]) + "." + std::to_string(ip[3]);
    }
    
    // Simple IPv6 hex formatting
    char buf[40];
    std::snprintf(buf, sizeof(buf), 
        "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
        ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
        ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]);
    return std::string(buf);
}

// -------------------------------------------------------------
//  AppType to human-readable string
// -------------------------------------------------------------
std::string appTypeToString(AppType t) {
    switch (t) {
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::FTP:        return "FTP";
        case AppType::SSH:        return "SSH";
        case AppType::SMTP:       return "SMTP";
        case AppType::NTP:        return "NTP";
        case AppType::TLS_OTHER:  return "TLS";
        case AppType::GOOGLE:     return "Google";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::TWITTER:    return "Twitter";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::CLOUDFLARE: return "Cloudflare";
        case AppType::GITHUB:     return "GitHub";
        case AppType::BITTORRENT: return "BitTorrent";
        case AppType::QUIC:       return "QUIC";
        case AppType::ICMP:       return "ICMP";
        case AppType::ARP:        return "ARP";
        default:                  return "Unknown";
    }
}

// -------------------------------------------------------------
//  SNI hostname to AppType
//
//  Ordered from most-specific to least-specific so subdomains
//  (e.g. googlevideo.com for YouTube) are caught before the
//  broader "google" pattern.
// -------------------------------------------------------------
AppType sniToAppType(const std::string& raw_sni) {
    // Lowercase for case-insensitive matching
    std::string sni = raw_sni;
    std::transform(sni.begin(), sni.end(), sni.begin(),
                   [](unsigned char c){ return std::tolower(c); });

    // YouTube (must come before google)
    if (sni.find("youtube")       != std::string::npos) return AppType::YOUTUBE;
    if (sni.find("googlevideo")   != std::string::npos) return AppType::YOUTUBE;
    if (sni.find("ytimg")         != std::string::npos) return AppType::YOUTUBE;

    // Google
    if (sni.find("google")        != std::string::npos) return AppType::GOOGLE;
    if (sni.find("googleapis")    != std::string::npos) return AppType::GOOGLE;
    if (sni.find("gstatic")       != std::string::npos) return AppType::GOOGLE;

    // Instagram (must come before facebook)
    if (sni.find("instagram")     != std::string::npos) return AppType::INSTAGRAM;
    if (sni.find("cdninstagram")  != std::string::npos) return AppType::INSTAGRAM;

    // Facebook
    if (sni.find("facebook")      != std::string::npos) return AppType::FACEBOOK;
    if (sni.find("fbcdn")         != std::string::npos) return AppType::FACEBOOK;
    if (sni.find("whatsapp")      != std::string::npos) return AppType::FACEBOOK;

    // Netflix
    if (sni.find("netflix")       != std::string::npos) return AppType::NETFLIX;
    if (sni.find("nflxvideo")     != std::string::npos) return AppType::NETFLIX;

    // Amazon
    if (sni.find("amazon")        != std::string::npos) return AppType::AMAZON;
    if (sni.find("amazonaws")     != std::string::npos) return AppType::AMAZON;
    if (sni.find("cloudfront")    != std::string::npos) return AppType::AMAZON;
    if (sni.find("twitch")        != std::string::npos) return AppType::AMAZON;

    // Microsoft
    if (sni.find("microsoft")     != std::string::npos) return AppType::MICROSOFT;
    if (sni.find("windows")       != std::string::npos) return AppType::MICROSOFT;
    if (sni.find("azure")         != std::string::npos) return AppType::MICROSOFT;
    if (sni.find("office365")     != std::string::npos) return AppType::MICROSOFT;
    if (sni.find("outlook")       != std::string::npos) return AppType::MICROSOFT;

    // Twitter / X
    if (sni.find("twitter")       != std::string::npos) return AppType::TWITTER;
    if (sni.find("twimg")         != std::string::npos) return AppType::TWITTER;
    if (sni.find("t.co")          != std::string::npos) return AppType::TWITTER;

    // Cloudflare
    if (sni.find("cloudflare")    != std::string::npos) return AppType::CLOUDFLARE;
    if (sni.find("1.1.1.1")       != std::string::npos) return AppType::CLOUDFLARE;

    // GitHub
    if (sni.find("github")        != std::string::npos) return AppType::GITHUB;

    // If we have any SNI but didn't match a known service, it's generic TLS
    if (!sni.empty()) return AppType::TLS_OTHER;

    return AppType::UNKNOWN;
}

// -------------------------------------------------------------
//  Flow helper implementations
// -------------------------------------------------------------
double Flow::durationSec() const noexcept {
    if (first_ts_sec == 0) return 0.0;
    double start = double(first_ts_sec) + double(first_ts_usec) / 1e6;
    double end   = double(last_ts_sec)  + double(last_ts_usec)  / 1e6;
    return end - start;
}

double Flow::throughputBps() const noexcept {
    double d = durationSec();
    return d > 0 ? double(byte_count) * 8.0 / d : 0.0;
}
