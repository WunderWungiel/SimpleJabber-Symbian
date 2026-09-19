/* SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
 * AES-128/256 with CBC/PKCS#7 and GCM, plain C (see aes.c). */
#ifndef SJ_AES_H
#define SJ_AES_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned char rk[240];   /* expanded key, up to 15 round keys */
    int rounds;
} aes_ctx;

typedef struct {
    aes_ctx aes;
    unsigned long long HH[16];
    unsigned long long HL[16];
} aes_gcm_ctx;

/* keylen is 16 or 32. Returns 0 on success. */
int aes_set_key(aes_ctx *ctx, const unsigned char *key, int keylen);
void aes_encrypt_block(const aes_ctx *ctx, const unsigned char in[16], unsigned char out[16]);
void aes_decrypt_block(const aes_ctx *ctx, const unsigned char in[16], unsigned char out[16]);

/* out must have room for len rounded up to the next multiple of 16 (always at least +1).
 * Returns the ciphertext length. */
unsigned long aes_cbc_pkcs7_encrypt(const aes_ctx *ctx, const unsigned char iv[16],
                                    const unsigned char *in, unsigned long len, unsigned char *out);
/* Returns the plaintext length, or -1 on bad length/padding. out needs len bytes. */
long aes_cbc_pkcs7_decrypt(const aes_ctx *ctx, const unsigned char iv[16],
                           const unsigned char *in, unsigned long len, unsigned char *out);

int aes_gcm_set_key(aes_gcm_ctx *g, const unsigned char *key, int keylen);
/* 96-bit IV, ciphertext is the same length as the plaintext, 16-byte tag. */
void aes_gcm_encrypt(const aes_gcm_ctx *g, const unsigned char iv[12],
                     const unsigned char *aad, unsigned long aadlen,
                     const unsigned char *in, unsigned long len, unsigned char *out, unsigned char tag[16]);
/* Returns 0 when the tag verifies; otherwise -1 and out is zeroed. */
int aes_gcm_decrypt(const aes_gcm_ctx *g, const unsigned char iv[12],
                    const unsigned char *aad, unsigned long aadlen,
                    const unsigned char *in, unsigned long len, unsigned char *out, const unsigned char tag[16]);

#ifdef __cplusplus
}
#endif

#endif
