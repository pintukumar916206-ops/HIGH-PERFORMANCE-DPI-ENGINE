#pragma once

#include <atomic>
#include <vector>
#include <memory>
#include <cstdint>
#include <algorithm>
#include "compat.h"

// ----------------------------------------------------------------------------
//  LockFreeQueue (MPMC Ring Buffer)
// ----------------------------------------------------------------------------
//  This is a 'Bounded MPMC' queue inspired by Erik Rigtorp's design.
//  It uses atomics with acquire/release memory orders to avoid mutex overhead.
//  In a DPI pipeline, this keeps the reader and workers running at line rate.
// ----------------------------------------------------------------------------
template<typename T>
class LockFreeQueue {
public:
    explicit LockFreeQueue(size_t capacity)
        : capacity_(capacity), head_(0), tail_(0) {
        // Capacity must be a power of 2 for fast seat-selection
        if (capacity < 1 || (capacity & (capacity - 1)) != 0) {
            // Basic alignment for portfolio purposes
            size_t p2 = 1;
            while (p2 < capacity) p2 <<= 1;
            capacity_ = p2;
        }
        
        slots_ = std::make_unique<Slot[]>(capacity_);
        for (size_t i = 0; i < capacity_; ++i) {
            slots_[i].sequence.store(i, std::memory_order_relaxed);
        }
        mask_ = capacity_ - 1;
    }

    // Producer side: pushes an item into the ring.
    // Returns false only if the queue is shut down.
    bool push(T&& data) {
        Slot* slot;
        size_t pos = tail_.load(std::memory_order_relaxed);
        for (;;) {
            if (shutdown_.load(std::memory_order_relaxed)) return false;
            slot = &slots_[pos & mask_];
            size_t seq = slot->sequence.load(std::memory_order_acquire);
            intptr_t diff = (intptr_t)seq - (intptr_t)pos;
            if (diff == 0) {
                if (tail_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed))
                    break;
            } else if (diff < 0) {
                // Queue is full—spin (in production, we might yield or pause)
                pos = tail_.load(std::memory_order_relaxed);
            } else {
                pos = tail_.load(std::memory_order_relaxed);
            }
        }

        slot->data = std::move(data);
        slot->sequence.store(pos + 1, std::memory_order_release);
        return true;
    }

    // Consumer side: pops an item.
    // Returns nullopt if empty or shut down.
    compat::optional<T> pop() {
        Slot* slot;
        size_t pos = head_.load(std::memory_order_relaxed);
        for (;;) {
            slot = &slots_[pos & mask_];
            size_t seq = slot->sequence.load(std::memory_order_acquire);
            intptr_t diff = (intptr_t)seq - (intptr_t)(pos + 1);
            if (diff == 0) {
                if (head_.compare_exchange_weak(pos, pos + 1, std::memory_order_relaxed))
                    break;
            } else if (diff < 0) {
                // Queue is empty
                if (shutdown_.load(std::memory_order_relaxed)) return compat::nullopt;
                pos = head_.load(std::memory_order_relaxed);
            } else {
                pos = head_.load(std::memory_order_relaxed);
            }
        }

        T result = std::move(slot->data);
        slot->sequence.store(pos + mask_ + 1, std::memory_order_release);
        return result;
    }

    void shutdown() { shutdown_.store(true, std::memory_order_relaxed); }

private:
    struct Slot {
        std::atomic<size_t> sequence;
        T data;
    };

    size_t capacity_;
    size_t mask_;
    std::unique_ptr<Slot[]> slots_;
    
    // Aligned to avoid false sharing on the hot path
    alignas(64) std::atomic<size_t> head_;
    alignas(64) std::atomic<size_t> tail_;
    std::atomic<bool> shutdown_{false};
};
