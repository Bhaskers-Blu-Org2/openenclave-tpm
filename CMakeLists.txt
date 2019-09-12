# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.10)

project("TPM Sample" LANGUAGES C)

# Collect Git info
if (IS_DIRECTORY "${PROJECT_SOURCE_DIR}/.git")
  # Install Git pre-commit hook
  if (NOT WIN32)
    file(
      COPY scripts/pre-commit
      DESTINATION "${PROJECT_SOURCE_DIR}/.git/hooks")
  endif ()
endif ()

# Generates `compile_commands.json` used by some developers. Only
# supported by Makefile and Ninja generators, but is otherwise
# ignored.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(tpm2-tss)
add_subdirectory(tpm)
add_subdirectory(enc)
add_subdirectory(host)

add_custom_target(run
  DEPENDS tpm_enclave tpm_host
  COMMAND sudo ${CMAKE_BINARY_DIR}/host/tpm_host ${CMAKE_BINARY_DIR}/enc/tpm_enclave.signed)

add_custom_target(debug
  DEPENDS ${CMAKE_BINARY_DIR}/host/tpm_host ${CMAKE_BINARY_DIR}/enc/tpm_enclave.signed
  COMMAND sudo $<TARGET_FILE:openenclave::oegdb> --tui --args ${CMAKE_BINARY_DIR}/host/tpm_host ${CMAKE_BINARY_DIR}/enc/tpm_enclave.signed)
