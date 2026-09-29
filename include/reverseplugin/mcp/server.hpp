#pragma once

#include <cstddef>
#include <istream>
#include <mutex>
#include <ostream>
#include <string>

#include "reverseplugin/mcp/tool_registry.hpp"
#include "reverseplugin/runtime/thread_pool.hpp"

namespace reverseplugin::mcp {

class Server final {
 public:
  Server(ToolRegistry registry, std::istream& input, std::ostream& output,
         std::size_t worker_count);
  [[nodiscard]] int run();

 private:
  static constexpr std::size_t max_message_bytes = 8U * 1024U * 1024U;

  [[nodiscard]] bool read_message(std::string& message);
  void dispatch(Json request);
  void handle_tool_call(Json id, Json params);
  void write(Json response);
  [[nodiscard]] Json initialize(const Json& params) const;
  [[nodiscard]] Json call_tool(std::string_view name, const Json& arguments) const;
  [[nodiscard]] static Json success(Json id, Json result);
  [[nodiscard]] static Json error(Json id, int code, std::string message,
                                  Json data = nullptr);

  ToolRegistry registry_;
  std::istream& input_;
  std::ostream& output_;
  std::mutex output_mutex_;
  runtime::ThreadPool workers_;
};

}  // namespace reverseplugin::mcp
