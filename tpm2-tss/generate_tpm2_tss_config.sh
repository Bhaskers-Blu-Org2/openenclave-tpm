#!/bin/bash

CFLAGS="`pkg-config oeenclave-gcc --cflags` -I/home/paulall/openenclave/3rdparty/openssl/Linux/package/include -DNO_DL="

CXXFLAGS="`pkg-config oeenclave-g++ --cflags`"

LDFLAGS="-L/home/paulall/openenclave/3rdparty/openssl/Linux/package/lib -loe_tssl_crypto"

SGXTSS_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd $SGXTSS_ROOT/tpm2-tss

./bootstrap
./configure --disable-tcti-mssim CFLAGS="${CFLAGS}" CXXFLAGS="${CXXFLAGS}" LDFLAGS="${LDFLAGS}" 
