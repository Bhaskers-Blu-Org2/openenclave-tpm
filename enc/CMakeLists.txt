# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT tpm_t.h tpm_t.c
  DEPENDS ${CMAKE_SOURCE_DIR}/tpm.edl
  COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/tpm.edl)
add_executable(tpm_enclave enc.c ${CMAKE_CURRENT_BINARY_DIR}/tpm_t.c)
target_include_directories(tpm_enclave PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/tpm2-tss/tpm2-tss/include/tss2)
target_link_directories(tpm_enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/tpm2-tss)
target_link_libraries(tpm_enclave openenclave::oeenclave openenclave::oelibc tpm2-tss )
