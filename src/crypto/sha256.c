/* SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
 * SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 2104) and HKDF-SHA256 (RFC 5869). Plain C89. */
#include "sha256.h"

#include <string.h>

static const unsigned long K256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL, 0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define U32(x) ((x) & 0xffffffffUL)

static void sha256_block(sha256_ctx *ctx, const unsigned char *p)
{
    unsigned long w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; ++i)
        w[i] = ((unsigned long)p[4 * i] << 24) | ((unsigned long)p[4 * i + 1] << 16) |
               ((unsigned long)p[4 * i + 2] << 8) | (unsigned long)p[4 * i + 3];
    for (i = 16; i < 64; ++i) {
        unsigned long s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned long s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = U32(w[i - 16] + s0 + w[i - 7] + s1);
    }
    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2]; d = ctx->h[3];
    e = ctx->h[4]; f = ctx->h[5]; g = ctx->h[6]; h = ctx->h[7];
    for (i = 0; i < 64; ++i) {
        unsigned long S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        unsigned long ch = (e & f) ^ ((~e) & g);
        unsigned long S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        unsigned long maj = (a & b) ^ (a & c) ^ (b & c);
        t1 = U32(h + S1 + ch + K256[i] + w[i]);
        t2 = U32(S0 + maj);
        h = g; g = f; f = e; e = U32(d + t1);
        d = c; c = b; b = a; a = U32(t1 + t2);
    }
    ctx->h[0] = U32(ctx->h[0] + a); ctx->h[1] = U32(ctx->h[1] + b);
    ctx->h[2] = U32(ctx->h[2] + c); ctx->h[3] = U32(ctx->h[3] + d);
    ctx->h[4] = U32(ctx->h[4] + e); ctx->h[5] = U32(ctx->h[5] + f);
    ctx->h[6] = U32(ctx->h[6] + g); ctx->h[7] = U32(ctx->h[7] + h);
}

void sha256_init(sha256_ctx *ctx)
{
    ctx->h[0] = 0x6a09e667UL; ctx->h[1] = 0xbb67ae85UL; ctx->h[2] = 0x3c6ef372UL; ctx->h[3] = 0xa54ff53aUL;
    ctx->h[4] = 0x510e527fUL; ctx->h[5] = 0x9b05688cUL; ctx->h[6] = 0x1f83d9abUL; ctx->h[7] = 0x5be0cd19UL;
    ctx->len = 0;
    ctx->buflen = 0;
}

void sha256_update(sha256_ctx *ctx, const unsigned char *data, unsigned long len)
{
    ctx->len += len;
    while (len > 0) {
        unsigned long take = 64 - ctx->buflen;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->buflen, data, take);
        ctx->buflen += take;
        data += take;
        len -= take;
        if (ctx->buflen == 64) {
            sha256_block(ctx, ctx->buf);
            ctx->buflen = 0;
        }
    }
}

void sha256_final(sha256_ctx *ctx, unsigned char out[32])
{
    unsigned long long bits = (unsigned long long)ctx->len * 8;
    unsigned char pad = 0x80;
    unsigned char lenbytes[8];
    int i;
    sha256_update(ctx, &pad, 1);
    while (ctx->buflen != 56) {
        unsigned char zero = 0;
        sha256_update(ctx, &zero, 1);
    }
    for (i = 0; i < 8; ++i) lenbytes[i] = (unsigned char)(bits >> (56 - 8 * i));
    sha256_update(ctx, lenbytes, 8);
    for (i = 0; i < 8; ++i) {
        out[4 * i] = (unsigned char)(ctx->h[i] >> 24);
        out[4 * i + 1] = (unsigned char)(ctx->h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(ctx->h[i] >> 8);
        out[4 * i + 3] = (unsigned char)(ctx->h[i]);
    }
    memset(ctx, 0, sizeof(*ctx));
}

void sha256(const unsigned char *data, unsigned long len, unsigned char out[32])
{
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

void hmac_sha256(const unsigned char *key, unsigned long keylen,
                 const unsigned char *data, unsigned long len, unsigned char out[32])
{
    unsigned char k[64], ipad[64], opad[64], inner[32];
    sha256_ctx ctx;
    int i;
    memset(k, 0, 64);
    if (keylen > 64) sha256(key, keylen, k);
    else memcpy(k, key, keylen);
    for (i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, inner);
    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, out);
    memset(k, 0, 64); memset(ipad, 0, 64); memset(opad, 0, 64);
}

void hkdf_sha256(const unsigned char *salt, unsigned long saltlen,
                 const unsigned char *ikm, unsigned long ikmlen,
                 const unsigned char *info, unsigned long infolen,
                 unsigned char *out, unsigned long outlen)
{
    unsigned char prk[32], t[32], block[32 + 256 + 1];
    unsigned long tlen = 0, done = 0;
    unsigned char counter = 1;
    if (infolen > 256) infolen = 256;   /* far beyond anything the protocol uses */
    hmac_sha256(salt, saltlen, ikm, ikmlen, prk);
    while (done < outlen) {
        unsigned long take;
        memcpy(block, t, tlen);
        memcpy(block + tlen, info, infolen);
        block[tlen + infolen] = counter;
        hmac_sha256(prk, 32, block, tlen + infolen + 1, t);
        tlen = 32;
        take = outlen - done < 32 ? outlen - done : 32;
        memcpy(out + done, t, take);
        done += take;
        ++counter;
    }
    memset(prk, 0, 32); memset(t, 0, 32); memset(block, 0, sizeof(block));
}
