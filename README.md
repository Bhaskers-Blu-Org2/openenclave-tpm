# openenclave-tpm
Prototype, work in progress, example of how to access the TPM from within an openenclave enclave.

This project depends on tpm2-tss which is a submodule. Make sure you do this:
```bash
git clone --recurse-submodules https://github.com/whatever/openenclave-tpm
```

This will pull down the submodule properly during clone.

Note that this is using experimental code that is not released from https://github.com/microsoft/openenclave.

