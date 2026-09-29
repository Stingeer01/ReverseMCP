#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace reverseplugin::runtime {

class ThreadPool final {
 public:
  explicit ThreadPool(std::size_t worker_count);
  ~ThreadPool();

  ThreadPool(const ThreadPool&) = delete;
  ThreadPool& operator=(const ThreadPool&) = delete;

  template <typename Function>
    requires std::invocable<Function&>
  void submit(Function&& function) {
    {
      std::lock_guard lock(mutex_);
      tasks_.emplace_back(std::forward<Function>(function));
    }
    ready_.notify_one();
  }

 private:
  void run(std::stop_token stop);

  std::mutex mutex_;
  std::condition_variable_any ready_;
  std::deque<std::move_only_function<void()>> tasks_;
  std::vector<std::jthread> workers_;
};

}  // namespace reverseplugin::runtime
