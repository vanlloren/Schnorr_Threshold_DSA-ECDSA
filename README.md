# Schnorr Threshold Signature Scheme (2-of-3)

A C implementation of a Schnorr signature scheme with two participants, enabling a threshold signing protocol where both parties must collaborate to produce a valid signature.

---

## Overview

This project implements a **2-of-3 threshold Schnorr signature scheme**, meaning that a valid signature can only be generated when both participants cooperate. Neither party alone can produce a valid signature, which provides strong security guarantees in distributed or multi-party settings.

The Schnorr signature scheme is renowned for its simplicity, efficiency, and strong security properties (provably secure under the discrete logarithm assumption in the random oracle model). The threshold extension further enhances security by eliminating any single point of failure or trust.

---

## How It Works

### Schnorr Signature Basics

A standard Schnorr signature over a group of prime order `q` with generator `G` works as follows:

- **Key generation**: Each signer holds a private key `x` and publishes a public key `X = x·G`.
- **Signing**: The signer picks a random nonce `k`, computes commitment `R = k·G`, computes challenge `e = H(R || message)`, and produces the response `s = k + e·x (mod q)`. The signature is `(R, s)`.
- **Verification**: Check that `s·G == R + e·X`.

### 2-of-3 Threshold Protocol

In the two-participant variant:

1. **Key generation**: Each participant `i` (for `i = 1, 2`) generates a private share `a_i` and publishes their public share `A_i = a_i·G`. The combined public key is `A = A_1 + A_2`.

3. **Nonce commitment**: Each participant independently picks a random nonce `k_i`, computes and shares their nonce commitment `R_i = k_i·G`. The combined nonce commitment is `R = R_1 + R_2`.

4. **Challenge computation**: Both participants compute the same challenge `e = H(R || message)`.

5. **Partial signatures**: Each participant computes their partial response `s_i = k_i + e·x_i (mod q)`.

6. **Signature aggregation**: The final signature is `(e, s)` where `s = s_1 + s_2 (mod q)`.

7. **Verification**: A standard Schnorr verification check confirms `s·G * e·A == R`.

---

## Dependencies

This implementation relies on the following cryptographic libraries:

### OpenSSL
Used for:
- Cryptographic hash functions (SHAKE-256 via `<openssl/sha.h>`)
- Secure random number generation (`RAND_bytes` via `<openssl/rand.h>`)

**Installation (Debian/Ubuntu):**
```bash
sudo apt-get install libssl-dev
```

**Installation (Fedora/RHEL):**
```bash
sudo dnf install openssl-devel
```

**Installation (macOS with Homebrew):**
```bash
brew install openssl
```

---

## Building

### Prerequisites

- C compiler (GCC or Clang)
- OpenSSL development libraries (see [Dependencies](#dependencies))

### Compile

```bash
gcc -o schnorr_threshold schnorr_threshold.c -lssl -lcrypto
```

If OpenSSL is installed in a non-standard location (e.g., via Homebrew on macOS):

```bash
gcc -o schnorr_threshold schnorr_threshold.c \
    -I$(brew --prefix openssl)/include \
    -L$(brew --prefix openssl)/lib \
    -lssl -lcrypto
```

---

## Usage

Run the compiled binary to execute the 2-of-3 threshold signing protocol:

```bash
./schnorr_threshold
```

The program will:
1. Generate key shares for both participants.
2. Run the interactive signing protocol on a sample message.
3. Aggregate the partial signatures.
4. Verify the resulting Schnorr signature against the combined public key.

---

## Security Considerations

- **Nonce secrecy**: Each participant's nonce (`k_i`) must be kept secret and used only once. Reusing a nonce or leaking it exposes the private key share.
- **Secure randomness**: Nonces must be generated using a cryptographically secure random number generator (provided by OpenSSL's `RAND_bytes`).
- **Elliptic curve**: The implementation uses the `secp256k1` curve (the same curve used by Bitcoin), which provides approximately 128-bit security strength.

---

## References

- C. P. Schnorr, *Efficient Signature Generation by Smart Cards*, Journal of Cryptology, 1991.
- T. Komlo and I. Goldberg, *FROST: Flexible Round-Optimized Schnorr Threshold Signatures*, SAC 2020. [https://eprint.iacr.org/2020/852](https://eprint.iacr.org/2020/852)
- OpenSSL Documentation: [https://www.openssl.org/docs/](https://www.openssl.org/docs/)

---

## License

See [LICENSE](LICENSE) for details.
