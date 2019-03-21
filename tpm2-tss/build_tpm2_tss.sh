#!/bin/bash


prefix=/home/paulall/openenclave-install
exec_prefix=${prefix}
includedir=${prefix}/include
libdir=${prefix}/lib


CFLAGS="-nostdinc -m64 -fPIE  -I${includedir}/openenclave/3rdparty/libc -I${includedir}/openenclave/3rdparty -I${includedir} -I/home/paulall/openenclave/3rdparty/openssl/Linux/package/include -DNO_DL="
CPPFLAGS="-nostdinc  -nostdinc++ -m64 -fPIE -I${includedir}/openenclave/3rdparty/libcxx -I${includedir}/openenclave/3rdparty/libc -I${includedir}/openenclave/3rdparty -I${includedir}"
#LDFLAGS=" -Wl,--no-undefined -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--export-dynamic -Wl,-pie -Wl,--build-id -L${libdir}/openenclave/enclave -loeenclave -L/home/paulall/openenclave/3rdparty/openssl/Linux/package/lib -loe_tssl_crypto  -loelibcxx -loelibc -loecore "
LDFLAGS=""

LDFLAGS="-L/home/paulall/openenclave/3rdparty/openssl/Linux/package/lib -loe_tssl_crypto"
SGXTSS_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $SGXTSS_ROOT

cd $SGXTSS_ROOT/tpm2-tss
./bootstrap
./configure --disable-tcti-mssim CFLAGS="${CFLAGS}" CXXFLAGS="${CPPFLAGS}" LDFLAGS="${LDFLAGS}" 
#make clean
#make
