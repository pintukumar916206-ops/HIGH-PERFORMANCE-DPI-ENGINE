#pragma once

#include <vector>
#include <queue>
#include <functional>
#include "compat.h"

namespace packet_analyzer::concurrency {

class ThreadPool {
public:
    explicit ThreadPool(size_t threads);
    ~ThreadPool();

    // Simplified enqueue without future support for MinGW compatibility
    void enqueue(std::function<void()> task) {
        {
            compat::lock_guard<compat::mutex> lock(queue_mutex);
            if(stop) throw std::runtime_error("enqueue on stopped ThreadPool");
            tasks.emplace(std::move(task));
        }
        condition.notify_one();
    }

private:
    std::vector<compat::thread> workers;
    std::queue<std::function<void()>> tasks;
    
    compat::mutex queue_mutex;
    compat::condition_variable condition;
    bool stop;
};

} // namespace packet_analyzer::concurrency
