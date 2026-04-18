#pragma once

#include <atomic>
#include <vector>
#include <memory>
#include <cstdint>
#include <algorithm>
#include "compat.h"

template<typename T>
class LockFreeQueue {
public:
    explicit LockFreeQueue(size_t capacity)
        : capacity_(capacity), head_(0), tail_(0) {
        if (capacity < 1 || (capacity & (capacity - 1)) != 0) {
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
                pos = tail_.load(std::memory_order_relaxed);
            } else {
                pos = tail_.load(std::memory_order_relaxed);
            }
        }

        slot->data = std::move(data);
        slot->sequence.store(pos + 1, std::memory_order_release);
        return true;
    }

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
    
    alignas(64) std::atomic<size_t> head_;
    alignas(64) std::atomic<size_t> tail_;
    std::atomic<bool> shutdown_{false};
};