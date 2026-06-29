cmake_minimum_required(VERSION 3.14)
project(http_parser LANGUAGES CXX)

include(FetchContent)

# --- Dependency: enum-reflection ---
# http_parser_enums.h does #include "enum.h" and defines its status/method/errno/
# state enums with the ENUM() macro. That header lives in the sibling
# enum-reflection library, pulled in here so the include resolves. Compiled as
# C++ (see below), enum.h's ENUM() expands to a real enum plus the reflective
# constexpr accessors, so the dependency is load-bearing, not just a path fixup.
# We track its tip with GIT_TAG main, like the rest of the family.
FetchContent_Declare(
  enum_reflection
  GIT_REPOSITORY https://github.com/Kronuz/enum-reflection.git
  GIT_TAG        main
)
FetchContent_MakeAvailable(enum_reflection)

# --- Library target ---
# http-parser is not header-only: http_parser.cc carries the ~2.4k-line state
# machine, so it must be compiled and linked. http_parser.h alone only declares
# the API. It is compiled as C++ so it pulls in enum.h's C++ machinery and
# matches the C++20 family; the file is C++-clean as written (the original
# Joyent parser uses enum casts that are already C++-valid). The implementation
# keeps its upstream content but takes a .cc extension so the C++ compile is
# first-class rather than relying on the deprecated "compile .c as C++" path.
add_library(http_parser http_parser.cc)
target_include_directories(http_parser PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_features(http_parser PUBLIC cxx_std_20)

# Link enum-reflection so "enum.h" is on the include path. PUBLIC because the
# public header http_parser.h -> http_parser_enums.h -> "enum.h", so consumers
# need it on their include path too.
target_link_libraries(http_parser PUBLIC enum_reflection::enum_reflection)

# Alias so consumers can link `http_parser::http_parser` whether they add this
# via add_subdirectory or FetchContent.
add_library(http_parser::http_parser ALIAS http_parser)

# Only build the test and demo when this repo is the top-level project, so
# consumers (e.g. via FetchContent) don't build them.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  enable_testing()
  add_executable(http_parser_test test/test.cc)
  target_link_libraries(http_parser_test PRIVATE http_parser)
  add_test(NAME http_parser COMMAND http_parser_test)

  # A runnable tour of the library (not a test): build & run ./build/http_parser_demo
  add_executable(http_parser_demo examples/demo.cc)
  target_link_libraries(http_parser_demo PRIVATE http_parser)
endif()
