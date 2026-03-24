#pragma once

#include "compat.h"
#include <deque>

// -------------------------------------------------------------
//  BoundedQueue - Thread-safe producer-consumer queue
// -------------------------------------------------------------
//  This is the backbone of the pipeline's backpressure mechanism.
//  A bounded queue prevents the reader from flooding memory when
//  workers can't keep up — once the queue is full the producer
//  either blocks (useful for live capture where we can't drop) or
//  the caller can check isFull() and discard the packet itself
//  (preferred for PCAP replay where timing is best-effort).
//
//  Thread safety:
//    Multiple producers and consumers are safe.
//    All public methods acquire the internal mutex.
//
//  Lifecycle:
//    - Normal operation: push() / pop() work as expected.
//    - Shutdown: call shutdown() when no more items will be pushed.
//      All blocked pop() callers will be woken and receive nullopt.
//      Remaining items in the queue are still drained before nullopt
//      is returned, so the consumer can process everything before exiting.
// -------------------------------------------------------------
template<typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity = 65536)
        : capacity_(capacity) {}

    // Push an item.  Blocks until space is available or the queue
    // is shut down.  Returns false if shut down (item NOT enqueued).
    bool push(T item) {
        compat::unique_lock<compat::mutex> lock(mu_);
        while (!(q_.size() < capacity_ || shutdown_)) {
            cv_not_full_.wait(lock);
        }
        if (shutdown_) return false;
        q_.push_back(std::move(item));
        lock.unlock();
        cv_not_empty_.notify_one();
        return true;
    }

    // Try to push without blocking.  Returns false if full or shut down.
    bool tryPush(T item) {
        compat::unique_lock<compat::mutex> lock(mu_);
        if (shutdown_ || q_.size() >= capacity_) return false;
        q_.push_back(std::move(item));
        lock.unlock();
        cv_not_empty_.notify_one();
        return true;
    }

    // Pop an item.  Blocks until one is available.
    // Returns compat::optional<T> when the queue is shut down AND empty.
    compat::optional<T> pop() {
        compat::unique_lock<compat::mutex> lock(mu_);
        while (!( !q_.empty() || shutdown_ )) {
            cv_not_empty_.wait(lock);
        }
        if (q_.empty()) return compat::nullopt;
        T item = std::move(q_.front());
        q_.pop_front();
        lock.unlock();
        cv_not_full_.notify_one();
        return item;
    }

    // Signal that no more items will be pushed.
    // Wakes all blocked pop() and push() callers.
    void shutdown() {
        {
            compat::lock_guard<compat::mutex> lock(mu_);
            shutdown_ = true;
        }
        cv_not_empty_.notify_all();
        cv_not_full_.notify_all();
    }

    size_t size() const {
        compat::lock_guard<compat::mutex> lock(mu_);
        return q_.size();
    }

    bool empty() const {
        compat::lock_guard<compat::mutex> lock(mu_);
        return q_.empty();
    }

    bool isFull() const {
        compat::lock_guard<compat::mutex> lock(mu_);
        return q_.size() >= capacity_;
    }

    size_t capacity() const noexcept { return capacity_; }

private:
    mutable compat::mutex      mu_;
    compat::condition_variable cv_not_empty_;
    compat::condition_variable cv_not_full_;
    std::deque<T>           q_;
    size_t                  capacity_;
    bool                    shutdown_ = false;
};
