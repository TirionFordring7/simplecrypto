cmake_minimum_required(VERSION 3.10)
project(encr)

set(CMAKE_C_STANDARD 11)

find_package(OpenSSL REQUIRED)

add_executable(encr ./main.c)

target_include_directories(encr PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(encr PRIVATE OpenSSL::Crypto)