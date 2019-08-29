# openenclave-tpm

Experimental, prototype, work in progress, example of how to access the TPM from within an Open Enclave enclave.
This project is built using libraries and headers from [Open Enclave SDK](https://github.com/openenclave/openenclave).

You will need an Intel SGX enabled machine or VM for this, along with the necessary SGX drivers.
Your machine or VM needs to have a TPM (or vTPM in the case of a VM).
Probably Linux only at this point, although [tpm2-tss SDK](https://github.com/tpm2-software/tpm2-tss) says Windows is experimentally supported.
I have not tried yet though.

You will need to install the [Open Enclave SDK](https://github.com/openenclave/openenclave). You can either enlist, build and install it, or you can just install a pre-built package. Make sure you install all the prerequisite packages. Once installed you will need to source the installed Open Enclave environment file so that this project can find libraries and headers.

This project also depends on the [Open Enclave OpenSSL repository](https://github.com/openenclave/openenclave-openssl). You will need to enlist, build and install based on the instructions in their readme file. This project expects the libraries to be installed in `/opt/oe-openssl`.

This project also depends on [tpm2-tss SDK](https://github.com/tpm2-software/tpm2-tss) as a sub-module. You will need to install all the prerequisite packages for this so we can build the library properly. We build the source for tpm2-tss as part of building our own binaries as the enclave has specific requirements.

Make sure you enlist this repository correctly so the sub-modules are enlisted properly:

```bash
git clone --recurse-submodules https://github.com/openenclave/openenclave-tpm
```

This will pull down the sub-module properly during clone.

Before building you will need to set up the [Open Enclave SDK](https://github.com/openenclave/openenclave) paths. Depending where you installed it to, you will need to source the `openenclaverc` bash script.
In my case it is like this:

```bash
. ~/openenclave-install/share/openenclave/openenclaverc
```

There are extra package manager environment setup mentioned on the openenclave-openssl repository readme.

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

Running it manually would look like this:

```bash
cd ~/openenclave-tpm/build
sudo host/tpm_host enc/tpm_enclave.signed
```

And when the code works this will be a great sample!

# Notes

* Access to the TPM is done through async file access. The enclave does not have direct access to these APIs and so we need to do an ocall from the enclave to the unsecure host. Open Enclave SDK does this for us so the TPM libraries call open() and our CRT will do what is necessary to make it work. If no encryption is used on the TPM operations the data passed around can be seen so secrets can be stolen. This sample has some tests that don't encrypt the session operations, and some that do. The enclave now uses the TEE seal key for encryption for those tests that enable the encryption.

* The tpm2-tss library uses OpenSSL. This library is used for various reasons, from random numbers to encryption. The default random number generator in OpenSSL in some cases call out to the processor RDTSC instruction which is not available from within the enclave as it is considered insecure. This is one of the reason we are depending on the Open Enclave OpenSSL repository rather than just using OpenSSL libraries directly.

# Contributing

This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the
instructions provided by the bot. You will only need to do this once across all
repositories using our CLA in the Open Enclave GitHub organization.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
