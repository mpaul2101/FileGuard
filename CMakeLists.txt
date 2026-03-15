cmake_minimum_required(VERSION 3.14)
project(fileguard LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(fileguard
    src/main.cpp
    src/file_type.cpp
    src/sha256.cpp
    src/scanner.cpp
    src/json_writer.cpp
)

target_include_directories(fileguard PRIVATE src)
target_link_libraries(fileguard PRIVATE OpenSSL::Crypto)

if(MSVC)
    target_compile_options(fileguard PRIVATE /W4)
else()
    target_compile_options(fileguard PRIVATE -Wall -Wextra -Wpedantic)
endif()
