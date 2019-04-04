# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# Create a library common to each of our three enclaves.
add_library(tpm_common STATIC tpm.c)
target_compile_options(tpm_common PUBLIC -fPIE)
target_link_libraries(tpm_common PUBLIC tpm2-tss)

target_include_directories(tpm_common PRIVATE
  ${CMAKE_SOURCE_DIR}/tpm2-tss/tpm2-tss/include/tss2)
