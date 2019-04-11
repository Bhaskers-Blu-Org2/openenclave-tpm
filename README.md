# openenclave-tpm
Experimental, prototype, work in progress, example of how to access the TPM from within an openenclave enclave.
This project is using unreleased code from the [Open Enclave SDK](https://github.com/microsoft/openenclave) from work-in-progress code branches.
In fact it uses cascading work in progress branches just to make it more clear that this should not be consumed by anyone yet!
Which is probably why it does not actually work!

You will need an SDX enabled machine or VM for this.
Your machine or VM needs to have a TPM.
Probably Linux only at this point, although [tpm2-tss SDK](https://github.com/tpm2-software/tpm2-tss) says Windows is experimental. 
I have not tried yet though.

You will need to build and install the [Open Enclave SDK](https://github.com/microsoft/openenclave), although the branch that you need to check-out is ever changing.
Currently it is `johnkord-openssl_6`.

This project depends on [tpm2-tss SDK](https://github.com/tpm2-software/tpm2-tss) as a submodule. 
Make sure you enlist properly to initialize and sync submodules:

```bash
git clone --recurse-submodules https://github.com/openenclave/openenclave-tpm
```
This will pull down the submodule properly during clone.

Before building you will need to set up the [Open Enclave SDK](https://github.com/microsoft/openenclave) paths. Depending where you installed it to, you will need to source the `openenclaverc` bash script.
In my case it is like this:
```bash
. ~/openenclave-install/share/openenclave/openenclaverc
```

Once cloned you can build like this:
```bash
cd openenclave-tpm
mkdir build
cd build
cmake ..
make
```

Best way to run or debug (in gdb) is like this due to the fact that you need to sudo and run the host with the enclave filename specified:
```bash
make run
make debug
```

And when the code works this will be a great sample!

# Notes

* Access to the TPM is done through async file access. The enclave does not have direct access to these APIs and so we need to do an ocall from the enclave to the unsecure host. OpenEnclave SDK's musl C runtime has does this for us so the TPM libraries call open() and our CRT will do what is necessary to make it work. If no encryption is used on the TPM operations the data passed around can be seen so secrets can be stolen. This sample does both at present.

* The TPM library uses openssl. This library is used for various reasons, from random numbers to encryption. The default random number generator in openssl in some cases call out to the processor RDTSC instruction which is not available from within the enclave as it is considered insecure. We are taking the openssl package from the Intel SGX SDK at present which patches some  usages of random number generation, but does not quite get all that are needed for the TPM library. As a result the openenclave snap of intels openssl library patches more of these so as to work around the lack of the processor instruction.