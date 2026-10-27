execute_process(COMMAND "${TOOL}" "${BASELINE}" "${CANDIDATE}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 10)
if(NOT result EQUAL 0)
  message(FATAL_ERROR "text example failed (${result}): ${error}")
endif()
if(NOT output MATCHES "\\[version\\] libcurl")
  message(FATAL_ERROR "text output did not include the expected version change: ${output}")
endif()

execute_process(COMMAND "${TOOL}" --format json "${BASELINE}" "${CANDIDATE}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 10)
if(NOT result EQUAL 0 OR NOT output MATCHES "\\\"changes\\\"")
  message(FATAL_ERROR "JSON output test failed (${result}): ${error} ${output}")
endif()

execute_process(COMMAND "${TOOL}" --fail-on added "${BASELINE}" "${CANDIDATE}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 10)
if(NOT result EQUAL 1)
  message(FATAL_ERROR "--fail-on added should exit 1, received ${result}: ${error}")
endif()

execute_process(COMMAND "${TOOL}" --deny-license curl "${BASELINE}" "${CANDIDATE}"
  RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 10)
if(NOT result EQUAL 1 OR NOT output MATCHES "denied license curl")
  message(FATAL_ERROR "--deny-license should reject curl (${result}): ${output} ${error}")
endif()
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/csv-baseline.json"
  "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[{\"name\":\"baseline\",\"version\":\"1\"}]}")
foreach(prefix IN ITEMS "=" "+" "-" "@" "＝" "＋" "－" "＠")
  file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/csv-formula.json"
    "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"components\":[{\"name\":\"baseline\",\"version\":\"1\"},{\"name\":\"${prefix}1+2\",\"version\":\"1\"}]}")
  execute_process(COMMAND "${TOOL}" --format csv
    "${CMAKE_CURRENT_BINARY_DIR}/csv-baseline.json" "${CMAKE_CURRENT_BINARY_DIR}/csv-formula.json"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 10 ENCODING UTF-8)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "CSV formula fixture failed: ${error}")
  endif()
  string(FIND "${output}" "\"${prefix}1+2\"" unsafe_cell)
  if(NOT unsafe_cell EQUAL -1)
    message(FATAL_ERROR "CSV exposes a formula-prefixed SBOM value: ${prefix}")
  endif()
  string(HEX "${prefix}" prefix_hex)
  string(SUBSTRING "${prefix_hex}" 0 2 first_byte)
  string(FIND "${output}" "\"\\x${first_byte}" escaped_cell)
  if(escaped_cell EQUAL -1)
    message(FATAL_ERROR "CSV did not render the unsafe prefix as literal hex: ${prefix}")
  endif()
  execute_process(COMMAND "${TOOL}" --format json
    "${CMAKE_CURRENT_BINARY_DIR}/csv-baseline.json" "${CMAKE_CURRENT_BINARY_DIR}/csv-formula.json"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 10 ENCODING UTF-8)
  string(FIND "${output}" "\"package\":\"${prefix}1+2\"" original_value)
  if(NOT result EQUAL 0 OR original_value EQUAL -1)
    message(FATAL_ERROR "JSON did not preserve the original package name: ${prefix} ${error}")
  endif()
endforeach()
