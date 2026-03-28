#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MLKEM_ALG OQS_KEM_alg_ml_kem_768
#define AES_KEY_SIZE 32
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16

/* HKDF using OpenSSL EVP (HKDF-SHA256) */
void derive_aes_key(const uint8_t *shared_secret, size_t ss_len, uint8_t *aes_key)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL)
    {
        fprintf(stderr, "HKDF context creation failed\n");
        exit(1);
    }

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, shared_secret, ss_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)"QuantumSafeFileEncryptor-v1", 29) <= 0)
    {
        fprintf(stderr, "HKDF setup failed\n");
        EVP_PKEY_CTX_free(pctx);
        exit(1);
    }

    size_t out_len = AES_KEY_SIZE;
    if (EVP_PKEY_derive(pctx, aes_key, &out_len) <= 0 || out_len != AES_KEY_SIZE)
    {
        fprintf(stderr, "HKDF derive failed\n");
        EVP_PKEY_CTX_free(pctx);
        exit(1);
    }

    EVP_PKEY_CTX_free(pctx);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage:\n  %s keygen\n  %s encrypt\n  %s decrypt\n", argv[0]);
        return 1;
    }

    OQS_KEM *kem = OQS_KEM_new(MLKEM_ALG);
    if (kem == NULL)
    {
        fprintf(stderr, "ML-KEM-768 not available\n");
        return 1;
    }

    if (strcmp(argv[1], "keygen") == 0)
    {
        uint8_t *pk = malloc(kem->length_public_key);
        uint8_t *sk = malloc(kem->length_secret_key);
        OQS_KEM_keypair(kem, pk, sk);

        FILE *f = fopen("pubkey.bin", "wb");
        fwrite(pk, 1, kem->length_public_key, f);
        fclose(f);
        f = fopen("secretkey.bin", "wb");
        fwrite(sk, 1, kem->length_secret_key, f);
        fclose(f);

        printf("ML-KEM-768 keypair generated (quantum-safe).\n");
        free(pk);
        free(sk);
    }
    else if (strcmp(argv[1], "encrypt") == 0)
    {
        // ML-KEM Encapsulation
        FILE *f = fopen("pubkey.bin", "rb");
        fseek(f, 0, SEEK_END);
        long pk_len = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *pk = malloc(pk_len);
        fread(pk, 1, pk_len, f);
        fclose(f);

        uint8_t *ct = malloc(kem->length_ciphertext);
        uint8_t *ss = malloc(kem->length_shared_secret);
        OQS_KEM_encaps(kem, ct, ss, pk);

        FILE *f_ct = fopen("kem_ct.bin", "wb");
        fwrite(ct, 1, kem->length_ciphertext, f_ct);
        fclose(f_ct);

        // === HKDF: Derive strong AES-256 key from ML-KEM shared secret ===
        uint8_t aes_key[AES_KEY_SIZE];
        derive_aes_key(ss, kem->length_shared_secret, aes_key);

        // AES-256-GCM Encryption
        uint8_t iv[GCM_IV_SIZE];
        RAND_bytes(iv, GCM_IV_SIZE);

        f = fopen("message.bin", "rb");
        fseek(f, 0, SEEK_END);
        long pt_len = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *pt = malloc(pt_len);
        fread(pt, 1, pt_len, f);
        fclose(f);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, iv);

        uint8_t *ct_aes = malloc(pt_len + GCM_TAG_SIZE);
        int len, ct_len = 0;
        EVP_EncryptUpdate(ctx, ct_aes, &len, pt, pt_len);
        ct_len += len;
        EVP_EncryptFinal_ex(ctx, ct_aes + ct_len, &len);
        ct_len += len;

        uint8_t tag[GCM_TAG_SIZE];
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag);
        EVP_CIPHER_CTX_free(ctx);

        // Write cipher.bin: [kem_ct][iv][tag][aes_ciphertext]
        f = fopen("cipher.bin", "wb");
        fwrite(ct, 1, kem->length_ciphertext, f);
        fwrite(iv, 1, GCM_IV_SIZE, f);
        fwrite(tag, 1, GCM_TAG_SIZE, f);
        fwrite(ct_aes, 1, ct_len, f);
        fclose(f);

        printf("✅ Hybrid encryption complete: ML-KEM-768 + HKDF-SHA256 + AES-256-GCM\n");
        free(pk);
        free(ct);
        free(ss);
        free(pt);
        free(ct_aes);
    }
    else if (strcmp(argv[1], "decrypt") == 0)
    {
        // ML-KEM Decapsulation
        FILE *f = fopen("kem_ct.bin", "rb");
        fseek(f, 0, SEEK_END);
        long ct_len = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *ct = malloc(ct_len);
        fread(ct, 1, ct_len, f);
        fclose(f);

        f = fopen("secretkey.bin", "rb");
        fseek(f, 0, SEEK_END);
        long sk_len = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint8_t *sk = malloc(sk_len);
        fread(sk, 1, sk_len, f);
        fclose(f);

        uint8_t *ss = malloc(kem->length_shared_secret);
        OQS_KEM_decaps(kem, ss, ct, sk);

        // HKDF: Derive the same AES key
        uint8_t aes_key[AES_KEY_SIZE];
        derive_aes_key(ss, kem->length_shared_secret, aes_key);

        // AES-256-GCM Decryption + Tag verification
        f = fopen("cipher.bin", "rb");
        uint8_t dummy[kem->length_ciphertext];
        fread(dummy, 1, kem->length_ciphertext, f); // skip KEM CT
        uint8_t iv[GCM_IV_SIZE];
        fread(iv, 1, GCM_IV_SIZE, f);
        uint8_t tag[GCM_TAG_SIZE];
        fread(tag, 1, GCM_TAG_SIZE, f);

        fseek(f, 0, SEEK_END);
        long total = ftell(f);
        long aes_ct_len = total - kem->length_ciphertext - GCM_IV_SIZE - GCM_TAG_SIZE;
        fseek(f, kem->length_ciphertext + GCM_IV_SIZE + GCM_TAG_SIZE, SEEK_SET);

        uint8_t *aes_ct = malloc(aes_ct_len);
        fread(aes_ct, 1, aes_ct_len, f);
        fclose(f);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, iv);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, tag);

        uint8_t *pt = malloc(aes_ct_len);
        int len, pt_len = 0;
        EVP_DecryptUpdate(ctx, pt, &len, aes_ct, aes_ct_len);
        pt_len += len;
        if (EVP_DecryptFinal_ex(ctx, pt + pt_len, &len) <= 0)
        {
            fprintf(stderr, "ERROR: AES-GCM authentication failed! Data may be tampered.\n");
            return 1;
        }
        pt_len += len;
        EVP_CIPHER_CTX_free(ctx);

        f = fopen("decrypted.bin", "wb");
        fwrite(pt, 1, pt_len, f);
        fclose(f);

        printf("Decryption successful (HKDF + AES-256-GCM integrity verified).\n");
        free(ct);
        free(sk);
        free(ss);
        free(aes_ct);
        free(pt);
    }

    OQS_KEM_free(kem);
    return 0;
}