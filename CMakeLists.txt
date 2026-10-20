cmake_minimum_required(VERSION 3.20)
project(SuperJumboInterop LANGUAGES C)

include(ExternalProject)
include(CTest)

if(NOT UNIX)
    message(FATAL_ERROR "The regression peer currently requires POSIX sockets.")
endif()

set(JUMBO_MAX_RECORD_SIZE "65535" CACHE STRING "wolfSSL maximum record size (4096..65535 for this test suite)")
set(JUMBO_WOLFSSL_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl_jumbo" CACHE PATH "wolfSSL source tree")
set(JUMBO_MBEDTLS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_jumbo" CACHE PATH "Mbed TLS source tree")
set(JUMBO_TEST_PORT "44550" CACHE STRING "Local TCP port for the regression tests")

if(NOT JUMBO_MAX_RECORD_SIZE MATCHES "^[0-9]+$" OR
   JUMBO_MAX_RECORD_SIZE LESS 4096 OR JUMBO_MAX_RECORD_SIZE GREATER 65535)
    message(FATAL_ERROR "JUMBO_MAX_RECORD_SIZE must be between 4096 and 65535 for this test suite.")
endif()
if(NOT JUMBO_TEST_PORT MATCHES "^[0-9]+$" OR
   JUMBO_TEST_PORT LESS 1024 OR JUMBO_TEST_PORT GREATER 65535)
    message(FATAL_ERROR "JUMBO_TEST_PORT must be between 1024 and 65535.")
endif()
foreach(source_dir IN ITEMS "${JUMBO_WOLFSSL_SOURCE_DIR}" "${JUMBO_MBEDTLS_SOURCE_DIR}")
    if(NOT EXISTS "${source_dir}/CMakeLists.txt")
        message(FATAL_ERROR "Missing implementation source tree: ${source_dir}")
    endif()
endforeach()

set(wolf_build "${CMAKE_CURRENT_BINARY_DIR}/wolfssl")
set(mbed_build "${CMAKE_CURRENT_BINARY_DIR}/mbedtls")
set(wolf_library "${wolf_build}/lib/${CMAKE_SHARED_LIBRARY_PREFIX}wolfssl${CMAKE_SHARED_LIBRARY_SUFFIX}")
set(mbed_server "${mbed_build}/programs/ssl/ssl_server2")
# Imported targets require their include directories to exist at configure time.
file(MAKE_DIRECTORY "${wolf_build}")

ExternalProject_Add(jumbo_wolfssl
    SOURCE_DIR "${JUMBO_WOLFSSL_SOURCE_DIR}"
    BINARY_DIR "${wolf_build}"
    CMAKE_ARGS
        "-DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}"
        "-DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}"
        "-DCMAKE_C_FLAGS:STRING=${CMAKE_C_FLAGS} -DWOLFSSL_MAX_RECORD_SIZE=${JUMBO_MAX_RECORD_SIZE}"
        "-DCMAKE_LIBRARY_OUTPUT_DIRECTORY:PATH=${wolf_build}/lib"
        -DBUILD_SHARED_LIBS:BOOL=ON
        -DWOLFSSL_TLS13:BOOL=ON
        -DWOLFSSL_EXAMPLES:BOOL=OFF
        -DWOLFSSL_CRYPT_TESTS:BOOL=OFF
    BUILD_BYPRODUCTS "${wolf_library}"
    BUILD_ALWAYS TRUE
    INSTALL_COMMAND ""
)
ExternalProject_Add(jumbo_mbedtls
    SOURCE_DIR "${JUMBO_MBEDTLS_SOURCE_DIR}"
    BINARY_DIR "${mbed_build}"
    CMAKE_ARGS
        "-DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}"
        "-DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}"
        "-DCMAKE_C_FLAGS:STRING=${CMAKE_C_FLAGS}"
        -DENABLE_PROGRAMS:BOOL=ON
        -DENABLE_TESTING:BOOL=OFF
        -DMBEDTLS_FATAL_WARNINGS:BOOL=OFF
    BUILD_COMMAND "${CMAKE_COMMAND}" --build <BINARY_DIR> --target ssl_server2 ssl_client2
    BUILD_BYPRODUCTS "${mbed_server}"
    BUILD_ALWAYS TRUE
    INSTALL_COMMAND ""
)

add_library(jumbo_wolfssl_library SHARED IMPORTED)
set_target_properties(jumbo_wolfssl_library PROPERTIES
    IMPORTED_LOCATION "${wolf_library}"
    INTERFACE_INCLUDE_DIRECTORIES "${wolf_build};${JUMBO_WOLFSSL_SOURCE_DIR}"
)
add_dependencies(jumbo_wolfssl_library jumbo_wolfssl)

add_executable(jumbo_overflow "${CMAKE_CURRENT_SOURCE_DIR}/tests/jumbo_overflow.c")
target_compile_definitions(jumbo_overflow PRIVATE WOLFSSL_MAX_RECORD_SIZE=${JUMBO_MAX_RECORD_SIZE})
target_link_libraries(jumbo_overflow PRIVATE jumbo_wolfssl_library)
set_target_properties(jumbo_overflow PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED YES)
add_dependencies(jumbo_overflow jumbo_mbedtls)

if(BUILD_TESTING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME jumbo_overflow
        COMMAND "${CMAKE_COMMAND}" -E env
            "JUMBO_HELPER=$<TARGET_FILE:jumbo_overflow>"
            "WOLF_SOURCE_DIR=${JUMBO_WOLFSSL_SOURCE_DIR}"
            "WOLF_BUILD=${wolf_build}"
            "MBED_BUILD=${mbed_build}"
            "JUMBO_TEST_PORT=${JUMBO_TEST_PORT}"
            "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/run_jumbo_overflow_tests.py"
    )
    set_tests_properties(jumbo_overflow PROPERTIES
        TIMEOUT 180
        RESOURCE_LOCK jumbo_tcp_port
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )
endif()
