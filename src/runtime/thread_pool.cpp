#include "reverseplugin/runtime/thread_pool.hpp"

#include <algorithm>
#include <utility>

namespace reverseplugin::runtime {

ThreadPool::ThreadPool(std::size_t worker_count) {
  const auto count = std::max<std::size_t>(1, worker_count);
  workers_.reserve(count);
  for (std::size_t i = 0; i < count; ++i) {
    workers_.emplace_back([this](std::stop_token stop) { run(stop); });
  }
}

ThreadPool::~ThreadPool() {
  for (auto& worker : workers_) {
    worker.request_stop();
  }
  ready_.notify_all();
}

void ThreadPool::run(std::stop_token stop) {
  while (true) {
    std::move_only_function<void()> task;
    {
      std::unique_lock lock(mutex_);
      ready_.wait(lock, stop, [this] { return !tasks_.empty(); });
      if (tasks_.empty()) {
        return;
      }
      task = std::move(tasks_.front());
      tasks_.pop_front();
    }
    task();
  }
}

}  // namespace reverseplugin::runtime
