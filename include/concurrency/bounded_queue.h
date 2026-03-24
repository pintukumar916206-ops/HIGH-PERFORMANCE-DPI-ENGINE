#pragma once

#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <atomic>

namespace packet_analyzer::concurrency {

template<typename T>
class BoundedQueue {
public:
    explicit BoundedQueue(size_t max_size) : max_size_(max_size) {}

    bool push(T&& item) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (queue_.size() >= max_size_) {
            dropped_count_++;
            return false; // Queue full, drop packet
        }
        queue_.push(std::move(item));
        total_pushed_++;
        condition_.notify_one();
        return true;
    }

    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        condition_.wait(lock, [this] { return !queue_.empty() || stop_; });
        
        if (stop_ && queue_.empty()) {
            return std::nullopt;
        }

        T item = std::move(queue_.front());
        queue_.pop();
        return item;
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stop_ = true;
        }
        condition_.notify_all();
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    uint64_t dropped_count() const { return dropped_count_; }
    uint64_t total_pushed() const { return total_pushed_; }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    size_t max_size_;
    bool stop_ = false;
    std::atomic<uint64_t> dropped_count_{0};
    std::atomic<uint64_t> total_pushed_{0};
};

} // namespace packet_analyzer::concurrency
