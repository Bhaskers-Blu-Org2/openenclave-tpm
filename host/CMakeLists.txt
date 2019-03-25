# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

add_custom_command(OUTPUT tpm_u.h tpm_u.c
  DEPENDS ${CMAKE_SOURCE_DIR}/tpm.edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/tpm.edl)

add_executable(tpm_host host.c ${CMAKE_CURRENT_BINARY_DIR}/tpm_u.c)

target_include_directories(tpm_host PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR})

# Temporary path for oeepoll_host library until it is put in the correct place
target_link_directories(tpm_host PRIVATE
  /home/paulall/openenclave-install/lib/openenclave/host)

# oeepoll_host library should be temporary until it is added to the proper oehostapp libraries
target_link_libraries(tpm_host oeepoll_host openenclave::oehostapp)
