#pragma once

#include "types.h"
#include "lpm_trie.h"
#include "aho_corasick.h"
#include <string>
#include <unordered_set>
#include <vector>
#include <atomic>
#include <cstdint>

class RuleEngine {
public:
  RuleEngine() = default;

  void addBlockIP(const std::string &cidr_or_ip);
  void addBlockDomain(const std::string &substring);
  void addBlockApp(AppType app);
  void addBlockPort(uint16_t port);

  int loadFromFile(const std::string &path);

  bool shouldBlock(const ParsedPacket &pkt, const Flow &flow) const noexcept;

  void buildAutomata() { if (!domain_matcher_.empty()) domain_matcher_.build(); }

  bool hasRules() const noexcept {
    return has_v4_rules_ || has_v6_rules_ || !domain_matcher_.empty() ||
           !blocked_apps_.empty() || !blocked_ports_.empty();
  }

  void printRules() const;

private:
  LpmTrie v4_trie_;
  LpmTrie v6_trie_;
  AhoCorasick domain_matcher_;
  bool has_v4_rules_ = false;
  bool has_v6_rules_ = false;
  std::unordered_set<uint16_t> blocked_ports_;
  std::unordered_set<uint8_t> blocked_apps_;

  void parseAndAddIP(const std::string &token);
};