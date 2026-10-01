# AES-256-GCM Demo (C++ / OpenSSL)

A small demo of authenticated encryption using OpenSSL's EVP API. It simulates a client encrypting a message and a server decrypting it, then proves tampering gets caught.

## Requirements

- g++ with C++11 or newer
- OpenSSL dev headers (`sudo apt install libssl-dev` on Debian/Ubuntu/WSL)

## Build & run

```bash
g++ aes_demo.cpp -lssl -lcrypto -o aes_demo
./aes_demo
```

## What it does

1. Generates a random 256-bit key (simulated key exchange).
2. Client encrypts a message with AES-256-GCM using a fresh random 96-bit IV.
3. Output blob layout: `IV (12 B) || ciphertext || auth tag (16 B)`.
4. Server splits the blob, verifies the tag, and decrypts.
5. Tamper test: flips one bit in the ciphertext and shows decryption fails.

## Why GCM and not CBC

- **Integrity built in:** the auth tag means modified ciphertext is rejected instead of decrypting to garbage.
- **No padding:** avoids padding-oracle attacks.
- **Rule:** never reuse an IV with the same key. This demo generates a new one per message.

## Limitations (it's a demo)

- Key never leaves the process. A real system would exchange it via RSA/ECDH/TLS.
- No associated data (AAD) is used.
- The key is wiped on destruction, but this isn't a hardened secrets-handling setup.
- Not audited. Don't ship it as-is.

## Files

- `aes_demo.cpp`: the whole demo
