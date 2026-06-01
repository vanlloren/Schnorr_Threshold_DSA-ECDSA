#include "secp256r1_rsakeys.h"
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

int secp256r1_rsa_keypair_generate(EVP_PKEY **pubkey, EVP_PKEY **privkey) {
    if (!pubkey || !privkey) return 0;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey_pair = NULL;
    EVP_PKEY *pub_only = NULL;
    int success = 0;

    *pubkey = NULL;
    *privkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 3072) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &pkey_pair) <= 0) goto cleanup;

    unsigned char temp_der[RSA3072_PUBLIC_KEY_SIZE];
    unsigned char *p_write = temp_der;
    int len = i2d_PublicKey(pkey_pair, &p_write);
    if (len <= 0 || len > RSA3072_PUBLIC_KEY_SIZE) goto cleanup;

    const unsigned char *p_read = temp_der;
    pub_only = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p_read, len);
    if (!pub_only) goto cleanup;

    *pubkey = pub_only;
    *privkey = pkey_pair;

    success = 1;

    cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (!success) {
        if (pkey_pair) EVP_PKEY_free(pkey_pair);
        if (pub_only) EVP_PKEY_free(pub_only);
    }
    return success;
}

int secp256r1_rsa_encrypt(
        unsigned char *ciphertext,
        const EVP_PKEY *pubkey,
        const unsigned char *plaintext,
        size_t *out_len
) {
    if (!ciphertext || !pubkey || !plaintext || !out_len) return 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)pubkey, NULL);
    if (!ctx) return 0;

    int success = 0;

    if (EVP_PKEY_encrypt_init(ctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) goto err;

    if (EVP_PKEY_encrypt(ctx, ciphertext, out_len, plaintext, RSA3072_PLAINTEXT_SIZE) <= 0) goto err;

    success = 1;

    err:
    EVP_PKEY_CTX_free(ctx);
    return success;
}

int secp256r1_rsa_decrypt(
        unsigned char *plaintext,
        EVP_PKEY *privkey,
        const unsigned char *ciphertext
) {
    if (!plaintext || !privkey || !ciphertext) return 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx) return 0;

    int success = 0;

    unsigned char temp_out[RSA3072_CIPHERTEXT_SIZE];
    size_t out_len = sizeof(temp_out);

    if (EVP_PKEY_decrypt_init(ctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) goto err;
    if (EVP_PKEY_decrypt(ctx, temp_out, &out_len, ciphertext, RSA3072_CIPHERTEXT_SIZE) <= 0) goto err;
    if (out_len != RSA3072_PLAINTEXT_SIZE) goto err;

    memcpy(plaintext, temp_out, out_len);

    success = 1;

    err:
    EVP_PKEY_CTX_free(ctx);
    return success;
}

int secp256r1_rsa_key_free(EVP_PKEY *pkey) {
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return 1;
}

int secp256r1_rsa_public_key_serialize(unsigned char *output, EVP_PKEY *pubkey) {
    if (!output || !pubkey) return 0;

    memset(output, 0, RSA3072_PUBLIC_KEY_SIZE);

    unsigned char *p_der = output;
    int len = i2d_PublicKey(pubkey, &p_der);

    if (len <= 0 || len > RSA3072_PUBLIC_KEY_SIZE) {
        return 0;
    }

    return 1;
}

int secp256r1_rsa_public_key_parse(EVP_PKEY **pubkey_out, const unsigned char *input) {
    if (!pubkey_out || !input) return 0;

    *pubkey_out = NULL;

    const unsigned char *p_der = input;

    EVP_PKEY *pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p_der, RSA3072_PUBLIC_KEY_SIZE);

    if (!pkey) {
        return 0;
    }

    *pubkey_out = pkey;
    return 1;
}