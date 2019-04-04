#!/bin/bash
export CC=clang-7
export CXX=clang++-7

CFLAGS="`pkg-config oeenclave-gcc --cflags` -I/home/paulall/openenclave/3rdparty/openssl/Linux/package/include -fPIE -DNO_DL="

CXXFLAGS="`pkg-config oeenclave-g++ --cflags`"

LDFLAGS=""
#LDFLAGS="`pkg-config oehost-g++ --libs`"
# -L/home/paulall/openenclave/3rdparty/openssl/Linux/package/lib -loe_tssl_crypto"

SGXTSS_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $SGXTSS_ROOT/tpm2-tss

./bootstrap
./configure --disable-tcti-mssim CFLAGS="${CFLAGS}" CXXFLAGS="${CXXFLAGS}" LDFLAGS="${LDFLAGS}" 
