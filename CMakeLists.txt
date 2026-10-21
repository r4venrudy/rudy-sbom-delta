cmake_minimum_required(VERSION 3.20)
project(rudy_sbom_delta VERSION 0.1.0 LANGUAGES CXX)

option(RUDY_SBOM_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(RUDY_SBOM_BUILD_TESTS "Build the test suite" ON)

add_library(rudy_sbom_core src/sbom.cpp)
target_include_directories(rudy_sbom_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(rudy_sbom_core PUBLIC cxx_std_20)
if(MSVC)
  target_compile_options(rudy_sbom_core PRIVATE /W4 /permissive- /EHsc)
else()
  target_compile_options(rudy_sbom_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

if(RUDY_SBOM_ENABLE_SANITIZERS AND NOT MSVC)
  target_compile_options(rudy_sbom_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(rudy_sbom_core PUBLIC -fsanitize=address,undefined)
endif()

add_executable(rudy-sbom-delta src/main.cpp)
target_link_libraries(rudy-sbom-delta PRIVATE rudy_sbom_core)

if(RUDY_SBOM_BUILD_TESTS)
  enable_testing()
  add_executable(rudy-sbom-tests tests/test.cpp)
  target_link_libraries(rudy-sbom-tests PRIVATE rudy_sbom_core)
  add_test(NAME rudy-sbom-tests COMMAND rudy-sbom-tests)
  add_test(NAME rudy-sbom-cli-integration
    COMMAND ${CMAKE_COMMAND}
      -DTOOL=$<TARGET_FILE:rudy-sbom-delta>
      -DBASELINE=${CMAKE_CURRENT_SOURCE_DIR}/examples/baseline.spdx.json
      -DCANDIDATE=${CMAKE_CURRENT_SOURCE_DIR}/examples/candidate.cdx.json
      -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli_test.cmake)
endif()

install(TARGETS rudy-sbom-delta RUNTIME DESTINATION bin)
