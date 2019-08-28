# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT tpm_t.h tpm_t.c tpm_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/tpm.edl
  COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/tpm.edl)

add_executable(tpm_enclave enc.c ${CMAKE_CURRENT_BINARY_DIR}/tpm_t.c)

target_link_directories(tpm_enclave PRIVATE /opt/oe-openssl/lib ${CMAKE_CURRENT_BINARY_DIR}/tpm2-tss )
target_link_libraries(tpm_enclave openenclave::oeenclave openenclave::oelibc openenclave::oehostepoll  openenclave::oehostfs tpm_common tpm2-tss liboeopensslcrypto.a)

target_include_directories(tpm_enclave PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/tpm2-tss/tpm2-tss/include/tss2)

# Generate key for signing enclave
add_custom_command(OUTPUT private_a.pem
  COMMAND openssl genrsa -out private_a.pem -3 3072)

# Sign tpm enclave key signing key
add_custom_command(OUTPUT tpm_enclave.signed
  DEPENDS tpm_enclave private_a.pem
  COMMAND openenclave::oesign sign --enclave-image tpm_enclave --config-file ${CMAKE_SOURCE_DIR}/enc/tpm.conf --key-file private_a.pem)

add_custom_target(sign ALL
    DEPENDS tpm_enclave.signed)
