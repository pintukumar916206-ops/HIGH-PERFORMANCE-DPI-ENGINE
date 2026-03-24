#pragma once
#include <vector>
#include <string>
#include <queue>
#include <algorithm>
#include <cstdint>
#include <map>

// Aho-Corasick automaton for multi-pattern domain matching.
// Optimized with a flat 256-way transition table for O(1) jumps.
class AhoCorasick {
public:
    AhoCorasick() {
        trie_.emplace_back(); // Root node
    }

    void addPattern(const std::string& pat) {
        int curr = 0;
        for (char c : pat) {
            unsigned char uc = static_cast<unsigned char>(c);
            if (trie_[curr].next[uc] == -1) {
                trie_[curr].next[uc] = static_cast<int>(trie_.size());
                trie_.emplace_back();
            }
            curr = trie_[curr].next[uc];
        }
        trie_[curr].is_terminal = true;
        built_ = false;
    }

    void build() {
        std::queue<int> q;
        for (int i = 0; i < 256; ++i) {
            if (trie_[0].next[i] != -1) {
                q.push(trie_[0].next[i]);
            } else {
                trie_[0].next[i] = 0; // Root's missing transitions go back to root
            }
        }

        while (!q.empty()) {
            int u = q.front();
            q.pop();

            for (int i = 0; i < 256; ++i) {
                int v = trie_[u].next[i];
                if (v != -1) {
                    trie_[v].fail = trie_[trie_[u].fail].next[i];
                    trie_[v].is_terminal |= trie_[trie_[v].fail].is_terminal;
                    q.push(v);
                } else {
                    trie_[u].next[i] = trie_[trie_[u].fail].next[i];
                }
            }
        }
        built_ = true;
    }

    bool match(const std::string& text) const {
        if (!built_ || trie_.empty()) return false;
        int curr = 0;
        for (char c : text) {
            unsigned char uc = static_cast<unsigned char>(c);
            curr = trie_[curr].next[uc];
            if (trie_[curr].is_terminal) return true;
        }
        return false;
    }

    bool empty() const { return trie_.size() <= 1; }

private:
    struct Node {
        int next[256];
        int fail = 0;
        bool is_terminal = false;
        Node() : fail(0), is_terminal(false) {
            for (int i = 0; i < 256; ++i) next[i] = -1;
        }
    };
    std::vector<Node> trie_;
    bool built_ = false;
};
