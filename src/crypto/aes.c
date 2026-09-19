/* SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
 * AES-128/256 (FIPS 197) with CBC/PKCS#7 and GCM (NIST SP 800-38D). Plain C, small and
 * table-light; GHASH uses Shoup's 4-bit tables so an encrypted picture decrypts in a
 * reasonable time on a 2011 ARM11. Not constant-time: fine for a chat client. */
#include "aes.h"

#include <string.h>

static const unsigned char SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static unsigned char INV_SBOX[256];
static int inv_sbox_ready = 0;

static void init_inv_sbox(void)
{
    int i;
    if (inv_sbox_ready) return;
    for (i = 0; i < 256; ++i) INV_SBOX[SBOX[i]] = (unsigned char)i;
    inv_sbox_ready = 1;
}

static unsigned char xtime(unsigned char x)
{
    return (unsigned char)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

static unsigned char gmul(unsigned char a, unsigned char b)
{
    unsigned char p = 0;
    int i;
    for (i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return p;
}

int aes_set_key(aes_ctx *ctx, const unsigned char *key, int keylen)
{
    int nk, i;
    unsigned char rcon = 1;
    unsigned char *w = ctx->rk;
    if (keylen == 16) { nk = 4; ctx->rounds = 10; }
    else if (keylen == 32) { nk = 8; ctx->rounds = 14; }
    else return -1;
    memcpy(w, key, keylen);
    for (i = nk; i < 4 * (ctx->rounds + 1); ++i) {
        unsigned char t[4];
        memcpy(t, w + 4 * (i - 1), 4);
        if (i % nk == 0) {
            unsigned char tmp = t[0];
            t[0] = SBOX[t[1]] ^ rcon; t[1] = SBOX[t[2]]; t[2] = SBOX[t[3]]; t[3] = SBOX[tmp];
            rcon = xtime(rcon);
        } else if (nk > 6 && i % nk == 4) {
            t[0] = SBOX[t[0]]; t[1] = SBOX[t[1]]; t[2] = SBOX[t[2]]; t[3] = SBOX[t[3]];
        }
        w[4 * i] = w[4 * (i - nk)] ^ t[0];
        w[4 * i + 1] = w[4 * (i - nk) + 1] ^ t[1];
        w[4 * i + 2] = w[4 * (i - nk) + 2] ^ t[2];
        w[4 * i + 3] = w[4 * (i - nk) + 3] ^ t[3];
    }
    init_inv_sbox();
    return 0;
}

static void add_round_key(unsigned char s[16], const unsigned char *rk)
{
    int i;
    for (i = 0; i < 16; ++i) s[i] ^= rk[i];
}

void aes_encrypt_block(const aes_ctx *ctx, const unsigned char in[16], unsigned char out[16])
{
    unsigned char s[16], t[16];
    int r, i;
    memcpy(s, in, 16);
    add_round_key(s, ctx->rk);
    for (r = 1; r <= ctx->rounds; ++r) {
        /* SubBytes + ShiftRows (column-major state: s[4*col + row]) */
        for (i = 0; i < 16; ++i) t[i] = SBOX[s[i]];
        for (i = 0; i < 16; ++i) {
            int row = i & 3, col = i >> 2;
            s[i] = t[4 * ((col + row) & 3) + row];
        }
        if (r != ctx->rounds) {
            /* MixColumns */
            for (i = 0; i < 4; ++i) {
                unsigned char a0 = s[4 * i], a1 = s[4 * i + 1], a2 = s[4 * i + 2], a3 = s[4 * i + 3];
                s[4 * i]     = (unsigned char)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
                s[4 * i + 1] = (unsigned char)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
                s[4 * i + 2] = (unsigned char)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
                s[4 * i + 3] = (unsigned char)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
            }
        }
        add_round_key(s, ctx->rk + 16 * r);
    }
    memcpy(out, s, 16);
}

void aes_decrypt_block(const aes_ctx *ctx, const unsigned char in[16], unsigned char out[16])
{
    unsigned char s[16], t[16];
    int r, i;
    memcpy(s, in, 16);
    add_round_key(s, ctx->rk + 16 * ctx->rounds);
    for (r = ctx->rounds - 1; r >= 0; --r) {
        /* InvShiftRows + InvSubBytes */
        for (i = 0; i < 16; ++i) {
            int row = i & 3, col = i >> 2;
            t[4 * ((col + row) & 3) + row] = s[i];
        }
        for (i = 0; i < 16; ++i) s[i] = INV_SBOX[t[i]];
        add_round_key(s, ctx->rk + 16 * r);
        if (r != 0) {
            /* InvMixColumns */
            for (i = 0; i < 4; ++i) {
                unsigned char a0 = s[4 * i], a1 = s[4 * i + 1], a2 = s[4 * i + 2], a3 = s[4 * i + 3];
                s[4 * i]     = (unsigned char)(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
                s[4 * i + 1] = (unsigned char)(gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
                s[4 * i + 2] = (unsigned char)(gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11));
                s[4 * i + 3] = (unsigned char)(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14));
            }
        }
    }
    memcpy(out, s, 16);
}

/* -- CBC with PKCS#7 --------------------------------------------------------------- */

unsigned long aes_cbc_pkcs7_encrypt(const aes_ctx *ctx, const unsigned char iv[16],
                                    const unsigned char *in, unsigned long len, unsigned char *out)
{
    unsigned char prev[16], block[16];
    unsigned long i, done = 0;
    unsigned char pad = (unsigned char)(16 - (len % 16));
    memcpy(prev, iv, 16);
    while (done + 16 <= len) {
        for (i = 0; i < 16; ++i) block[i] = in[done + i] ^ prev[i];
        aes_encrypt_block(ctx, block, out + done);
        memcpy(prev, out + done, 16);
        done += 16;
    }
    for (i = 0; i < 16; ++i) {
        unsigned char b = (done + i < len) ? in[done + i] : pad;
        block[i] = b ^ prev[i];
    }
    aes_encrypt_block(ctx, block, out + done);
    return done + 16;
}

long aes_cbc_pkcs7_decrypt(const aes_ctx *ctx, const unsigned char iv[16],
                           const unsigned char *in, unsigned long len, unsigned char *out)
{
    unsigned char prev[16], block[16];
    unsigned long i, done = 0;
    unsigned char pad;
    if (len == 0 || len % 16 != 0) return -1;
    memcpy(prev, iv, 16);
    while (done < len) {
        aes_decrypt_block(ctx, in + done, block);
        for (i = 0; i < 16; ++i) out[done + i] = block[i] ^ prev[i];
        memcpy(prev, in + done, 16);
        done += 16;
    }
    pad = out[len - 1];
    if (pad == 0 || pad > 16) return -1;
    for (i = 0; i < pad; ++i)
        if (out[len - 1 - i] != pad) return -1;
    return (long)(len - pad);
}

/* -- GCM ---------------------------------------------------------------------------- */

typedef unsigned long long u64;

static const u64 LAST4[16] = {
    0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
    0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

static u64 get_be64(const unsigned char *p)
{
    return ((u64)p[0] << 56) | ((u64)p[1] << 48) | ((u64)p[2] << 40) | ((u64)p[3] << 32) |
           ((u64)p[4] << 24) | ((u64)p[5] << 16) | ((u64)p[6] << 8) | (u64)p[7];
}

static void put_be64(unsigned char *p, u64 v)
{
    int i;
    for (i = 0; i < 8; ++i) p[i] = (unsigned char)(v >> (56 - 8 * i));
}

static void gcm_gen_tables(aes_gcm_ctx *g)
{
    unsigned char h[16];
    u64 vh, vl;
    int i, j;
    memset(h, 0, 16);
    aes_encrypt_block(&g->aes, h, h);
    vh = get_be64(h);
    vl = get_be64(h + 8);
    g->HL[8] = vl;
    g->HH[8] = vh;
    g->HH[0] = 0;
    g->HL[0] = 0;
    for (i = 4; i > 0; i >>= 1) {
        u64 T = (vl & 1) * 0xe1000000ULL;
        vl = (vh << 63) | (vl >> 1);
        vh = (vh >> 1) ^ (T << 32);
        g->HL[i] = vl;
        g->HH[i] = vh;
    }
    for (i = 2; i <= 8; i *= 2)
        for (j = 1; j < i; ++j) {
            g->HH[i + j] = g->HH[i] ^ g->HH[j];
            g->HL[i + j] = g->HL[i] ^ g->HL[j];
        }
}

static void gcm_mult(const aes_gcm_ctx *g, unsigned char x[16])
{
    int i;
    unsigned char lo, hi, rem;
    u64 zh, zl;
    lo = x[15] & 0x0f;
    zh = g->HH[lo];
    zl = g->HL[lo];
    for (i = 15; i >= 0; --i) {
        lo = x[i] & 0x0f;
        hi = x[i] >> 4;
        if (i != 15) {
            rem = (unsigned char)(zl & 0x0f);
            zl = (zh << 60) | (zl >> 4);
            zh = zh >> 4;
            zh ^= LAST4[rem] << 48;
            zh ^= g->HH[lo];
            zl ^= g->HL[lo];
        }
        rem = (unsigned char)(zl & 0x0f);
        zl = (zh << 60) | (zl >> 4);
        zh = zh >> 4;
        zh ^= LAST4[rem] << 48;
        zh ^= g->HH[hi];
        zl ^= g->HL[hi];
    }
    put_be64(x, zh);
    put_be64(x + 8, zl);
}

int aes_gcm_set_key(aes_gcm_ctx *g, const unsigned char *key, int keylen)
{
    if (aes_set_key(&g->aes, key, keylen) != 0) return -1;
    gcm_gen_tables(g);
    return 0;
}

static void gcm_ghash_update(const aes_gcm_ctx *g, unsigned char y[16], const unsigned char *data, unsigned long len)
{
    unsigned long i, done = 0;
    while (done < len) {
        unsigned long take = len - done < 16 ? len - done : 16;
        for (i = 0; i < take; ++i) y[i] ^= data[done + i];
        gcm_mult(g, y);
        done += take;
    }
}

static void gcm_crypt(const aes_gcm_ctx *g, const unsigned char iv[12],
                      const unsigned char *aad, unsigned long aadlen,
                      const unsigned char *in, unsigned long len, unsigned char *out,
                      int encrypt, unsigned char tag[16])
{
    unsigned char j0[16], ctr[16], ks[16], y[16], lenblock[16];
    unsigned long done = 0, i;
    memcpy(j0, iv, 12);
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    memcpy(ctr, j0, 16);
    memset(y, 0, 16);
    gcm_ghash_update(g, y, aad, aadlen);
    while (done < len) {
        unsigned long take = len - done < 16 ? len - done : 16;
        /* increment the 32-bit counter */
        for (i = 15; i >= 12; --i) if (++ctr[i] != 0) break;
        aes_encrypt_block(&g->aes, ctr, ks);
        for (i = 0; i < take; ++i) out[done + i] = in[done + i] ^ ks[i];
        gcm_ghash_update(g, y, encrypt ? out + done : in + done, take);
        done += take;
    }
    put_be64(lenblock, (u64)aadlen * 8);
    put_be64(lenblock + 8, (u64)len * 8);
    gcm_ghash_update(g, y, lenblock, 16);
    aes_encrypt_block(&g->aes, j0, ks);
    for (i = 0; i < 16; ++i) tag[i] = y[i] ^ ks[i];
}

void aes_gcm_encrypt(const aes_gcm_ctx *g, const unsigned char iv[12],
                     const unsigned char *aad, unsigned long aadlen,
                     const unsigned char *in, unsigned long len, unsigned char *out, unsigned char tag[16])
{
    gcm_crypt(g, iv, aad, aadlen, in, len, out, 1, tag);
}

int aes_gcm_decrypt(const aes_gcm_ctx *g, const unsigned char iv[12],
                    const unsigned char *aad, unsigned long aadlen,
                    const unsigned char *in, unsigned long len, unsigned char *out, const unsigned char tag[16])
{
    unsigned char computed[16];
    unsigned char diff = 0;
    int i;
    gcm_crypt(g, iv, aad, aadlen, in, len, out, 0, computed);
    for (i = 0; i < 16; ++i) diff |= (unsigned char)(computed[i] ^ tag[i]);
    if (diff) {
        memset(out, 0, len);
        return -1;
    }
    return 0;
}
