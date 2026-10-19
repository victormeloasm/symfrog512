# Prebuilt reference binary (Linux x86-64)

This folder contains the experimental **SymFrog-512 AEAD v5-SIV** CLI binary built in the test environment. It has been tested against the installed `libsodium.so.23` runtime and OpenSSL 3, but the runtime did not provide the official `libsodium-dev` headers. For development or publication, compile the C++ source on your own target system against genuine headers:

```bash
sudo apt install clang lld make libsodium-dev libssl-dev
make release
```

The GitHub repository should be treated as a source-first research artifact. Linux distribution/runtime and ABI differences may prevent the prebuilt binary from running.
