#pragma once

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "reverseplugin/mcp/tool.hpp"
#include "reverseplugin/process/process_manager.hpp"

namespace reverseplugin::tools {

inline mcp::ToolError invalid(std::string message, mcp::Json details = {}) {
  return {.code = mcp::ToolErrorCode::invalid_arguments,
          .message = std::move(message),
          .details = std::move(details)};
}

inline mcp::ToolError process_error(const process::Error& error) {
  return {.code = mcp::ToolErrorCode::unavailable,
          .message = error.message,
          .details = {{"native_code", error.native_code}}};
}

inline std::expected<std::uint64_t, mcp::ToolError> unsigned_value(
    const mcp::Json& object, std::string_view key) {
  const auto entry = object.find(key);
  if (entry == object.end()) {
    return std::unexpected(invalid("Missing required argument", {{"argument", key}}));
  }
  if (entry->is_number_unsigned()) {
    return entry->get<std::uint64_t>();
  }
  if (entry->is_number_integer()) {
    const auto value = entry->get<std::int64_t>();
    if (value >= 0) {
      return static_cast<std::uint64_t>(value);
    }
  }
  if (entry->is_string()) {
    const auto& text = entry->get_ref<const std::string&>();
    auto view = std::string_view{text};
    int base = 10;
    if (view.starts_with("0x") || view.starts_with("0X")) {
      view.remove_prefix(2);
      base = 16;
    }
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(view.data(), view.data() + view.size(), value, base);
    if (error == std::errc{} && end == view.data() + view.size()) {
      return value;
    }
  }
  return std::unexpected(invalid("Argument must be an unsigned integer or hexadecimal string",
                                 {{"argument", key}, {"received", *entry}}));
}

inline std::string hex_u64(std::uint64_t value) {
  std::array<char, 18> buffer{};
  buffer[0] = '0';
  buffer[1] = 'x';
  const auto [end, error] = std::to_chars(buffer.data() + 2, buffer.data() + buffer.size(), value, 16);
  if (error != std::errc{}) {
    return {};
  }
  return std::string(buffer.data(), end);
}

inline std::string hex_bytes(std::span<const std::byte> bytes) {
  constexpr std::string_view digits = "0123456789abcdef";
  std::string result(bytes.size() * 2, '0');
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    const auto value = std::to_integer<unsigned char>(bytes[i]);
    result[i * 2] = digits[value >> 4U];
    result[i * 2 + 1] = digits[value & 0x0FU];
  }
  return result;
}

inline std::expected<std::vector<std::byte>, mcp::ToolError> parse_hex_bytes(
    std::string_view text, std::size_t maximum = 65536) {
  if (text.empty() || (text.size() & 1U) != 0)
    return std::unexpected(invalid("hex must contain a non-empty even number of digits"));
  if (text.size() / 2 > maximum)
    return std::unexpected(invalid("hex payload exceeds the permitted byte count"));
  std::vector<std::byte> result(text.size() / 2);
  for (std::size_t i = 0; i < result.size(); ++i) {
    unsigned value = 0;
    const auto* first = text.data() + i * 2;
    const auto [last, error] = std::from_chars(first, first + 2, value, 16);
    if (error != std::errc{} || last != first + 2)
      return std::unexpected(invalid("hex contains a non-hexadecimal character",
                                     {{"character_offset", i * 2}}));
    result[i] = static_cast<std::byte>(value);
  }
  return result;
}

inline std::shared_ptr<const process::ProcessSession> require_session(
    const mcp::Json& arguments, const std::shared_ptr<process::ProcessManager>& processes,
    mcp::ToolError& error) {
  auto id = unsigned_value(arguments, "session_id");
  if (!id) {
    error = std::move(id.error());
    return nullptr;
  }
  auto session = processes->session(*id);
  if (!session) {
    error = invalid("Unknown or detached process session", {{"session_id", *id}});
  }
  return session;
}

inline const mcp::Json& read_only_annotations() {
  static const mcp::Json value{{"readOnlyHint", true},
                               {"destructiveHint", false},
                               {"idempotentHint", true},
                               {"openWorldHint", false}};
  return value;
}

inline const mcp::Json& session_schema() {
  static const mcp::Json value{{"type", "integer"},
                               {"minimum", 1},
                               {"description", "Opaque session identifier returned by attach_process."}};
  return value;
}

inline const mcp::Json& address_schema() {
  static const mcp::Json value{
      {"description", "Virtual address as an unsigned integer or 0x-prefixed hexadecimal string. Prefer hexadecimal strings to preserve 64-bit precision."},
      {"oneOf", {{{"type", "integer"}, {"minimum", 0}},
                  {{"type", "string"}, {"pattern", "^0[xX][0-9a-fA-F]+$"}}}}};
  return value;
}

}  // namespace reverseplugin::tools
