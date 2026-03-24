#pragma once

#include <cstdint>
#include <memory>
#include <vector>

// Binary prefix trie for Longest Prefix Match (LPM).
class LpmTrie {
public:
    LpmTrie() : root_(std::make_unique<Node>()) {}

    // Insert a prefix. bits is the number of significant bits.
    void insert(const uint8_t* addr, int bits) {
        Node* curr = root_.get();
        for (int i = 0; i < bits; ++i) {
            int bit = (addr[i / 8] >> (7 - (i % 8))) & 1;
            if (bit == 0) {
                if (!curr->left) curr->left = std::make_unique<Node>();
                curr = curr->left.get();
            } else {
                if (!curr->right) curr->right = std::make_unique<Node>();
                curr = curr->right.get();
            }
        }
        curr->is_terminal = true;
    }

    // Returns true if any prefix matched (standard LPM block)
    bool match(const uint8_t* addr, int max_bits) const {
        Node* curr = root_.get();
        if (curr->is_terminal) return true;

        for (int i = 0; i < max_bits; ++i) {
            int bit = (addr[i / 8] >> (7 - (i % 8))) & 1;
            if (bit == 0) {
                if (!curr->left) return false;
                curr = curr->left.get();
            } else {
                if (!curr->right) return false;
                curr = curr->right.get();
            }
            if (curr->is_terminal) return true;
        }
        return false;
    }

private:
    struct Node {
        std::unique_ptr<Node> left;
        std::unique_ptr<Node> right;
        bool is_terminal = false;
    };
    std::unique_ptr<Node> root_;
};
