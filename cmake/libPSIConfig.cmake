# these are just pass through config file for the ones that are placed in the build directory.


include("${CMAKE_CURRENT_LIST_DIR}/preamble.cmake")

if(NOT EXISTS "${VOLEPSI_BUILD_DIR}")
    message(FATAL_ERROR "failed to find the volePSI build directory. Looked at VOLEPSI_BUILD_DIR: ${VOLEPSI_BUILD_DIR}\n Please set it manually.")
endif()

include("${VOLEPSI_BUILD_DIR}/volePSIConfig.cmake")