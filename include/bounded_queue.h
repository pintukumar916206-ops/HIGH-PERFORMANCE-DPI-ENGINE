#pragma once

#include "compat.h"
#include <deque>

template<typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t capacity = 65536)
        : capacity_(capacity) {}

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

    bool tryPush(T item) {
        compat::unique_lock<compat::mutex> lock(mu_);
        if (shutdown_ || q_.size() >= capacity_) return false;
        q_.push_back(std::move(item));
        lock.unlock();
        cv_not_empty_.notify_one();
        return true;
    }

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
