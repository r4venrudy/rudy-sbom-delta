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
