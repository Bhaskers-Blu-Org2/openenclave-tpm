# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# directory under the binaries directory where we copy tpm2-tss to.
# Under this directory we do the auto configure
set(TPM2_TSS_DIR ${CMAKE_CURRENT_BINARY_DIR}/tpm2-tss)

# Only need this to generate the config.h file, but it generates loads of other files so we need
# to do the whole thing in the binary directory
include (ExternalProject)
ExternalProject_Add(tpm2-tss-external
  DOWNLOAD_COMMAND
    ${CMAKE_COMMAND} -E copy_directory
      ${CMAKE_CURRENT_LIST_DIR}/tpm2-tss
      ${TPM2_TSS_DIR}
  CONFIGURE_COMMAND
    ${CMAKE_COMMAND} -E chdir ${TPM2_TSS_DIR} /bin/bash -x ${TPM2_TSS_DIR}/bootstrap
  COMMAND
    ${CMAKE_COMMAND} -E chdir ${TPM2_TSS_DIR} /bin/bash -x ${TPM2_TSS_DIR}/configure --disable-tcti-mssim --enable-nodl --with-crypto=ossl --disable-doxygen-doc --disable-doxygen-man --disable-doxygen-rtf --disable-doxygen-html --disable-shared 
  BUILD_COMMAND 
    ${CMAKE_COMMAND} -E chdir ${TPM2_TSS_DIR} make -j
  INSTALL_COMMAND 
    ${CMAKE_COMMAND} -E copy
    ${TPM2_TSS_DIR}/src/tss2-mu/.libs/libtss2-mu.a
    ${CMAKE_CURRENT_BINARY_DIR}/libtss2-mu.a
  COMMAND
    ${CMAKE_COMMAND} -E copy
    ${TPM2_TSS_DIR}/src/tss2-sys/.libs/libtss2-sys.a
    ${CMAKE_CURRENT_BINARY_DIR}/libtss2-sys.a
  COMMAND
    ${CMAKE_COMMAND} -E copy
    ${TPM2_TSS_DIR}/src/tss2-esys/.libs/libtss2-esys.a
    ${CMAKE_CURRENT_BINARY_DIR}/libtss2-esys.a
  COMMAND
    ${CMAKE_COMMAND} -E copy
    ${TPM2_TSS_DIR}/src/tss2-rc/.libs/libtss2-rc.a
    ${CMAKE_CURRENT_BINARY_DIR}/libtss2-rc.a
  COMMAND
    ${CMAKE_COMMAND} -E copy
    ${TPM2_TSS_DIR}/src/tss2-tcti/.libs/libtss2-tctildr.a
    ${CMAKE_CURRENT_BINARY_DIR}/libtss2-tctildr.a
  COMMAND
    ${CMAKE_COMMAND} -E copy
    ${TPM2_TSS_DIR}/src/tss2-tcti/.libs/libtss2-tcti-device.a
    ${CMAKE_CURRENT_BINARY_DIR}/libtss2-tcti-device.a
  COMMAND
    ${CMAKE_COMMAND} -E copy
    ${TPM2_TSS_DIR}/.libs/libutil.a
    ${CMAKE_CURRENT_BINARY_DIR}/libutil.a
    )

# Clean the exteral directory and copied libraries
set_property(DIRECTORY PROPERTY ADDITIONAL_MAKE_CLEAN_FILES 
  ${TPM2_TSS_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}/libtss2-mu.a
  ${CMAKE_CURRENT_BINARY_DIR}/libtss2-sys.a
  ${CMAKE_CURRENT_BINARY_DIR}/libtss2-esys.a
  ${CMAKE_CURRENT_BINARY_DIR}/libtss2-rc.a
  ${CMAKE_CURRENT_BINARY_DIR}/libtss2-tctildr.a
  ${CMAKE_CURRENT_BINARY_DIR}/libtss2-tcti-device.a
  ${CMAKE_CURRENT_BINARY_DIR}/libutil.a
)
