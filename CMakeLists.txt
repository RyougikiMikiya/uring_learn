cmake_minimum_required(VERSION 3.0.0)
project(karenstore VERSION 0.1.0)

include(CTest)
enable_testing()

set(CMAKE_CXX_STANDARD 17)

include_directories(libpcap)

# set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -fpermissive)

add_subdirectory(libpcap)

add_executable(uring_pcap_copy uring_test.cpp)

# target_compile_options(mytest PRIVATE -fpermissive)

add_executable(uring_cp uring_cp.c)

target_link_libraries(uring_pcap_copy PRIVATE pcap uring)

target_link_libraries(uring_cp PRIVATE uring)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
