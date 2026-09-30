cmake_minimum_required(VERSION 3.25)

project(reverseplugin VERSION 1.1.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "ReversePlugin process introspection currently requires Windows")
endif()

include(FetchContent)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

FetchContent_Declare(
  nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  zydis
  GIT_REPOSITORY https://github.com/zyantific/zydis.git
  GIT_TAG v4.1.1
  GIT_SHALLOW TRUE
  GIT_SUBMODULES_RECURSE TRUE
)
FetchContent_MakeAvailable(zydis)

add_library(reverseplugin_sdk STATIC
  src/analysis/analysis_cache.cpp
  src/analysis/binary_image.cpp
  src/analysis/binary_store.cpp
  src/analysis/function_analyzer.cpp
  src/analysis/static_index.cpp
  src/mcp/server.cpp
  src/mcp/tool_registry.cpp
  src/runtime/thread_pool.cpp
  src/process/process_manager.cpp
  src/memory/pattern.cpp
  src/memory/snapshot_store.cpp
  src/debug/debug_engine.cpp
  src/debug/debug_context.cpp
  src/debug/stack_walker.cpp
  src/disasm/zydis_disassembler.cpp
  src/il2cpp/game_assembly.cpp
  src/il2cpp/metadata.cpp
  src/il2cpp/workspace_store.cpp
  src/tools/process_control_tools.cpp
  src/tools/memory_tools.cpp
  src/tools/memory_analysis_tools.cpp
  src/tools/memory_snapshot_tools.cpp
  src/tools/debug_tools.cpp
  src/tools/debug_execution_tools.cpp
  src/tools/debug_stack_tools.cpp
  src/tools/binary_analysis_tools.cpp
  src/tools/binary_navigation_tools.cpp
  src/tools/binary_index_tools.cpp
  src/tools/il2cpp_tools.cpp
  src/tools/server_info.cpp
)
target_include_directories(reverseplugin_sdk PUBLIC include)
target_link_libraries(reverseplugin_sdk PUBLIC nlohmann_json::nlohmann_json Zydis)
target_compile_definitions(reverseplugin_sdk PUBLIC REVERSEPLUGIN_VERSION="${PROJECT_VERSION}")

if(MSVC)
  target_compile_options(reverseplugin_sdk PRIVATE /W4 /WX /permissive- /EHsc /utf-8)
  target_link_libraries(reverseplugin_sdk PRIVATE Psapi Dbghelp Bcrypt)
else()
  target_compile_options(reverseplugin_sdk PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(reverseplugin-mcp src/main.cpp)
target_link_libraries(reverseplugin-mcp PRIVATE reverseplugin_sdk)

include(CTest)
if(BUILD_TESTING)
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  add_test(NAME reverseplugin-knowledge-tests
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/validate_knowledge.py
            ${CMAKE_SOURCE_DIR}/skills)

  add_executable(reverseplugin-tests tests/sdk_tests.cpp)
  target_link_libraries(reverseplugin-tests PRIVATE reverseplugin_sdk)
  add_test(NAME reverseplugin-tests COMMAND reverseplugin-tests)

  add_executable(reverseplugin-stress-tests tests/stress_tests.cpp)
  target_link_libraries(reverseplugin-stress-tests PRIVATE reverseplugin_sdk)
  add_test(NAME reverseplugin-stress-tests COMMAND reverseplugin-stress-tests)
  set_tests_properties(reverseplugin-stress-tests PROPERTIES LABELS "stress" TIMEOUT 180)

  add_executable(reverseplugin-il2cpp-tests tests/il2cpp_tests.cpp)
  target_link_libraries(reverseplugin-il2cpp-tests PRIVATE reverseplugin_sdk)
  add_test(NAME reverseplugin-il2cpp-tests COMMAND reverseplugin-il2cpp-tests)

  add_executable(reverseplugin-debug-target tests/debug_target.cpp)

  add_executable(reverseplugin-debug-integration-tests tests/debug_integration_tests.cpp)
  target_link_libraries(reverseplugin-debug-integration-tests PRIVATE reverseplugin_sdk)
  add_dependencies(reverseplugin-debug-integration-tests reverseplugin-debug-target)
  add_test(NAME reverseplugin-debug-integration-tests COMMAND reverseplugin-debug-integration-tests)
  set_tests_properties(reverseplugin-debug-integration-tests PROPERTIES TIMEOUT 30)
endif()
