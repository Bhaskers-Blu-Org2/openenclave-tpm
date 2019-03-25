# openenclave-tpm
Experimental, prototype, work in progress, example of how to access the TPM from within an openenclave enclave.
This project is using unreleased code from the [Open Enclave SDK](https://github.com/microsoft/openenclave) from work-in-progress code branches.
In fact it uses cascading work in progress branches just to make it more clear that this should not be consumed by anyone yet!
Which is probably why it does not actually!

You will need an SDX enabled machine or VM for this.
Your machine or VM needs to have a TPM.
Probably Linux only at this point, although [tpm2-tss SDK](https://github.com/tpm2-software/tpm2-tss) says Windows is experimental. 
I have not tried yet though.

You will need to build and install the [Open Enclave SDK](https://github.com/microsoft/openenclave), although the branch that you need to check-out is ever changing.
Currently it is `johnkord-openssl_5`.

This project depends on [tpm2-tss SDK](https://github.com/tpm2-software/tpm2-tss) as a submodule. 
Make sure you enlist properly to initialize and sync submodules:

```bash
git clone --recurse-submodules https://github.com/paulcallen/openenclave-tpm
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