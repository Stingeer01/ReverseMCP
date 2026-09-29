#include <Windows.h>

#include <cstdint>
#include <iostream>

namespace {

volatile std::uint64_t counter = 0;

__declspec(noinline) void breakpoint_target() {
  ++counter;
}

}  // namespace

int main() {
  std::cout << GetCurrentProcessId() << ' ' << GetCurrentThreadId() << ' '
            << reinterpret_cast<std::uintptr_t>(&breakpoint_target) << std::endl;
  for (std::size_t i = 0; i < 3000; ++i) {
    breakpoint_target();
    Sleep(10);
  }
}
