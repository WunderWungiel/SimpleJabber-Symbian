/* SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
 * SHA-256, HMAC-SHA256 and HKDF-SHA256 in plain C (see sha256.c). */
#ifndef SJ_SHA256_H
#define SJ_SHA256_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    unsigned long h[8];
    unsigned long long len;
    unsigned char buf[64];
    unsigned long buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *ctx);
void sha256_update(sha256_ctx *ctx, const unsigned char *data, unsigned long len);
void sha256_final(sha256_ctx *ctx, unsigned char out[32]);
void sha256(const unsigned char *data, unsigned long len, unsigned char out[32]);

void hmac_sha256(const unsigned char *key, unsigned long keylen,
                 const unsigned char *data, unsigned long len, unsigned char out[32]);

/* RFC 5869 extract-then-expand. */
void hkdf_sha256(const unsigned char *salt, unsigned long saltlen,
                 const unsigned char *ikm, unsigned long ikmlen,
                 const unsigned char *info, unsigned long infolen,
                 unsigned char *out, unsigned long outlen);

#ifdef __cplusplus
}
#endif

#endif
