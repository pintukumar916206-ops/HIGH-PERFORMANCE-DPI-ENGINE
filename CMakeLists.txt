cmake_minimum_required(VERSION 3.16)
project(NETWORK_TRAFFIC_ANALYSIS_ENGINE LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0600)
    if(MSVC)
        add_compile_options(/W4 /std:c++14)
    else()
        add_compile_options(-Wall -Wextra -std=c++14)
    endif()
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native -flto")
endif()

if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0600 -DNTDDI_VERSION=0x06000000)
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)

find_package(Threads REQUIRED)

find_package(PCAP)
if(PCAP_FOUND)
    include_directories(${PCAP_INCLUDE_DIR})
endif()

set(SOURCES
    src/types.cpp
    src/pcap_reader.cpp
    src/pcap_writer.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/flow_tracker.cpp
    src/rule_engine.cpp
    src/packet_pool.cpp
    src/dpi_pipeline.cpp
    src/live_capture.cpp
    src/http_proxy.cpp
    src/anomaly_detector.cpp
)

if(PCAP_FOUND)
    add_executable(traffic_engine src/main.cpp ${SOURCES})
    target_link_libraries(traffic_engine PRIVATE Threads::Threads ${PCAP_LIBRARY})
    if(WIN32)
        target_link_libraries(traffic_engine PRIVATE ws2_32)
    endif()

    add_executable(test_runner tests/test_runner.cpp ${SOURCES})
    target_link_libraries(test_runner PRIVATE Threads::Threads ${PCAP_LIBRARY})
    if(WIN32)
        target_link_libraries(test_runner PRIVATE ws2_32)
    endif()
else()
    message(WARNING "PCAP not found. Full traffic_engine will not be built. Building mock_engine instead.")
endif()

add_executable(mock_engine src/mock_main.cpp)

enable_testing()
add_test(NAME InternalTests COMMAND test_runner)
