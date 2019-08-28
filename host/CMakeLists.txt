# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT tpm_u.h tpm_u.c tpm_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/tpm.edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/tpm.edl)

add_executable(tpm_host host.c ${CMAKE_CURRENT_BINARY_DIR}/tpm_u.c)

target_include_directories(tpm_host PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/tpm2-tss/tpm2-tss/include/tss2)

# Temporary path for oeepoll_host library until it is put in the correct place
target_link_directories(tpm_host PRIVATE
  /home/paulall/openenclave-install/lib/openenclave/host
  ${CMAKE_CURRENT_BINARY_DIR}/tpm2-tss)

# oeepoll_host library should be temporary until it is added to the proper oehostapp libraries
target_link_libraries(tpm_host 
  openenclave::oehostapp 
  tpm_common
  tpm2-tss crypto)
