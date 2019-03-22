# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.10)

project("TPM Sample" LANGUAGES C)

find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(tpm2-tss)
add_subdirectory(enc)
add_subdirectory(host)


# Generate key for signing enclave
add_custom_command(OUTPUT private_a.pem
  COMMAND openssl genrsa -out private_a.pem -3 3072
  COMMAND openssl rsa -in private_a.pem -pubout -out public_a.pem)

# Sign tpm enclave key signing key
add_custom_command(OUTPUT enc/tpm_enclave.signed
  DEPENDS ${CMAKE_BINARY_DIR}/private_a.pem ${CMAKE_BINARY_DIR}/enc/tpm_enclave
  COMMAND openenclave::oesign sign ${CMAKE_BINARY_DIR}/enc/tpm_enclave ${CMAKE_SOURCE_DIR}/enc/tpm.conf private_a.pem)

add_custom_target(run
  DEPENDS tpm_host ${CMAKE_BINARY_DIR}/enc/tpm_enclave.signed
  COMMAND tpm_host ${CMAKE_BINARY_DIR}/enc/tpm_enclave.signed)

add_custom_target(sign
    DEPENDS ${CMAKE_BINARY_DIR}/enc/tpm_enclave.signed)

add_custom_target(debug
    DEPENDS ${CMAKE_BINARY_DIR}/enc/tpm_enclave.signed
    COMMAND oe-gdb --tui --args ${CMAKE_BINARY_DIR}/host/tpm_host ${CMAKE_BINARY_DIR}/enc/tpm_enclave.signed)