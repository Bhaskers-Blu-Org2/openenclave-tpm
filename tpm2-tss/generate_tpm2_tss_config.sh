#!/bin/bash
export CC=clang-7
export CXX=clang++-7

SGXTSS_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $SGXTSS_ROOT/tpm2-tss

./bootstrap
./configure --disable-tcti-mssim
