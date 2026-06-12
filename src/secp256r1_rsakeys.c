#include "secp256r1_rsakeys.h"
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/err.h>

int secp256r1_rsa_keypair_generate(EVP_PKEY **pubkey, EVP_PKEY **privkey) {
    if (!pubkey || !privkey) return 0;

    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey_pair = NULL;
    EVP_PKEY *pub_only = NULL;
    unsigned char *temp_der = NULL; // Diventa un puntatore allocato dinamicamente
    int success = 0;

    *pubkey = NULL;
    *privkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) goto cleanup;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto cleanup;

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_BITS) <= 0) goto cleanup;
    if (EVP_PKEY_keygen(ctx, &pkey_pair) <= 0) goto cleanup;

    // 1. Chiediamo a OpenSSL quanti byte reali servono per questa chiave (inclusi i metadati ASN.1)
    int len = i2d_PUBKEY(pkey_pair, NULL);
    if (len <= 0) goto cleanup;

    // 2. Allocazione dinamica sicura nell'Heap anziché nell'array fisso sullo Stack
    temp_der = malloc(len);
    if (!temp_der) goto cleanup;

    unsigned char *p_write = temp_der;
    // 3. Ora eseguiamo la serializzazione reale dentro lo spazio allocato al millimetro
    if (i2d_PUBKEY(pkey_pair, &p_write) <= 0) goto cleanup;

    const unsigned char *p_read = temp_der;
    pub_only = d2i_PUBKEY(NULL, &p_read, len);
    if (!pub_only) goto cleanup;

    *pubkey = pub_only;
    *privkey = pkey_pair;

    success = 1;

    cleanup:
    if (temp_der) free(temp_der); // Liberiamo sempre il buffer dinamico temporaneo
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

    if (EVP_PKEY_encrypt(ctx, ciphertext, out_len, plaintext, RSA_PLAINTEXT_SIZE) <= 0) goto err;

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
    unsigned char *temp_buffer = NULL;
    size_t out_len = 0;

    // 1. Inizializzazione standard dei parametri (devono essere identici alla cifratura)
    if (EVP_PKEY_decrypt_init(ctx) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) goto err;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) goto err;

    // 2. PRIMO PASSAGGIO (Chiamata a vuoto): Chiediamo a OpenSSL quanti byte vuole per elaborare il blocco.
    // Passando NULL, OpenSSL scriverà in out_len la dimensione del modulo (1920 byte a 256 bit).
    if (EVP_PKEY_decrypt(ctx, NULL, &out_len, ciphertext, RSA_CIPHERTEXT_SIZE) <= 0) goto err;

    // Allocazione dinamica del buffer temporaneo della dimensione esatta richiesta da OpenSSL
    temp_buffer = malloc(out_len);
    if (!temp_buffer) goto err;

    // 3. SECONDO PASSAGGIO: Eseguiamo la decifratura REALE dentro il buffer temporaneo capiente.
    // Al termine di questa chiamata, OpenSSL sovrascriverà 'out_len' con la lunghezza del dato REALE svestito dal padding OAEP.
    if (EVP_PKEY_decrypt(ctx, temp_buffer, &out_len, ciphertext, RSA_CIPHERTEXT_SIZE) <= 0) goto err;

    // 4. CONTROLLO DI SICUREZZA: Verifichiamo che i byte utili estratti non superino la capacità del nostro plaintext statico.
    // Se il dato estratto è valido (es. la coordinata della chiave), out_len sarà ad esempio 32 o 64 byte.
    if (out_len > RSA_PLAINTEXT_SIZE) {
        printf("[DEBUG] Errore logico: Il dato decifrato (%zu byte) supera la macro RSA_PLAINTEXT_SIZE (%d)\n", out_len, RSA_PLAINTEXT_SIZE);
        goto err;
    }

    // Copiamo i dati decifrati puliti nel buffer finale dello user
    memcpy(plaintext, temp_buffer, out_len);
    success = 1;

    err:
    if (temp_buffer) free(temp_buffer);

    // Stampa diagnostica solo in caso di effettivo fallimento matematico di OpenSSL
    if (!success) {
        unsigned long err_code = ERR_get_error();
        if (err_code != 0) {
            char err_msg[256];
            ERR_error_string_n(err_code, err_msg, sizeof(err_msg));
            printf("[OPENSSL CRITICAL ERROR] %s\n", err_msg);
        }
    }

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

    memset(output, 0, RSA_PUBLIC_KEY_SIZE);

    unsigned char *p_write = output;

    int len = i2d_PUBKEY(pubkey, &p_write);

    if (len <= 0 || len > RSA_PUBLIC_KEY_SIZE) {
        return 0;
    }

    return 1;
}

int secp256r1_rsa_public_key_parse(EVP_PKEY **pubkey_out, const unsigned char *input, size_t input_len) {
    if (!pubkey_out || !input) return 0;
    *pubkey_out = NULL;

    const unsigned char *p_read = input;
    // Passiamo input_len (cioè rsa_key_len) al posto di RSA_PUBLIC_KEY_SIZE
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p_read, input_len);

    if (!pkey) return 0;
    *pubkey_out = pkey;
    return 1;
}