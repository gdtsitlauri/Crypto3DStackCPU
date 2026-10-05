cmake_minimum_required(VERSION 3.16)
project(Crypto3DStackCPU LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
  add_compile_options(/W4)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Wno-unknown-pragmas)
endif()

add_library(crypto3d_core STATIC src/3d.cpp)
target_include_directories(crypto3d_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_library(crypto3d_vtf STATIC src/vtf_hls.cpp)
target_include_directories(crypto3d_vtf PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(crypto3d_vtf PUBLIC crypto3d_core)

function(c3d_test name source)
  add_executable(${name} ${source})
  target_link_libraries(${name} PRIVATE crypto3d_core)
  add_test(NAME ${name} COMMAND ${name})
endfunction()

enable_testing()
c3d_test(crypto_kat_test src/crypto_kat_test.cpp)
c3d_test(multilayer_memory_test src/multilayer_memory_test.cpp)
c3d_test(root_provisioning_test src/root_provisioning_test.cpp)

add_executable(vertical_trust_fabric_test src/vertical_trust_fabric_test.cpp)
target_link_libraries(vertical_trust_fabric_test PRIVATE crypto3d_vtf crypto3d_core)
add_test(NAME vertical_trust_fabric_test COMMAND vertical_trust_fabric_test)

# Memory encryption + integrity tree model (roadmap 2.1), checked against the
# independent Python reference vectors in src/mit_vectors.h.
c3d_test(memory_integrity_test src/memory_integrity_test.cpp)

add_executable(asm_to_hex src/asm_to_hex.cpp)
add_executable(encryptor_single src/encryptor.cpp)
target_link_libraries(encryptor_single PRIVATE crypto3d_core)
add_executable(decryptor_single src/decryptor.cpp)
target_link_libraries(decryptor_single PRIVATE crypto3d_core)
add_executable(crypto3d_cpu_test src/3d_test.cpp)
target_link_libraries(crypto3d_cpu_test PRIVATE crypto3d_core)

add_executable(vtf_property_test src/vtf_property_test.cpp)
target_link_libraries(vtf_property_test PRIVATE crypto3d_vtf crypto3d_core)
add_test(NAME vtf_property_test COMMAND vtf_property_test)

# Same testbench Vitis HLS uses for csim/cosim of the CMAC authenticator.
add_executable(vtf_hls_tb src/vtf_hls_tb.cpp)
target_link_libraries(vtf_hls_tb PRIVATE crypto3d_vtf crypto3d_core)
add_test(NAME vtf_hls_tb COMMAND vtf_hls_tb)

add_executable(vtf_benchmark src/vtf_benchmark.cpp)
target_link_libraries(vtf_benchmark PRIVATE crypto3d_vtf crypto3d_core)
