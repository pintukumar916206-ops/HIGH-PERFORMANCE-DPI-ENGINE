#include "concurrency/thread_pool.h"

namespace packet_analyzer::concurrency {

ThreadPool::ThreadPool(size_t threads) : stop(false) {
    for(size_t i = 0; i<threads; ++i)
        workers.emplace_back(
            [this] {
                for(;;) {
                    std::function<void()> task;
                    {
                        compat::lock_guard<compat::mutex> lock(this->queue_mutex);
                        this->condition.wait(this->queue_mutex,
                            [this]{ return this->stop || !this->tasks.empty(); });
                        if(this->stop && this->tasks.empty())
                            return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }
                    task();
                }
            }
        );
}

ThreadPool::~ThreadPool() {
    {
        compat::lock_guard<compat::mutex> lock(queue_mutex);
        stop = true;
    }
    condition.notify_all();
    for(compat::thread &worker: workers)
        worker.join();
}

} // namespace packet_analyzer::concurrency
