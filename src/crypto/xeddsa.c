/* SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
 *
 * Curve25519 key agreement and XEdDSA signatures, built on TweetNaCl (public domain,
 * tweetnacl.cr.yp.to). TweetNaCl's arithmetic is static, so the file is included rather
 * than linked and the Signal-specific routines are added on top of it here.
 *
 * XEdDSA (the "curve25519_sign" of libsignal's curve25519 library) signs with a
 * Montgomery/X25519 private key: the scalar is used directly as an Ed25519 secret scalar,
 * the Ed25519 public key A = aB is derived from it, and the sign bit of A is carried in
 * the top bit of S so the verifier - who only has the X25519 public key u - can rebuild
 * A from y = (u - 1) / (u + 1). Verification is plain Ed25519 after that. The nonce is
 * hashed from a domain-separation prefix, the private key, the message and 64 random
 * bytes, exactly as libsignal does it; verifiers never see the nonce, so only the sign
 * and verify equations have to match libsignal's - and they do.
 */
#include <stdlib.h>
#include "third_party/tweetnacl.c"

#include "xeddsa.h"

/* TweetNaCl expects the platform to supply randombytes(); the app installs a source. */
static void (*g_random_source)(unsigned char *, unsigned long long) = 0;

void nacl_set_random_source(void (*source)(unsigned char *, unsigned long long))
{
    g_random_source = source;
}

void randombytes(u8 *out, u64 len)
{
    if (g_random_source) g_random_source(out, len);
    else { u64 i; FOR(i, len) out[i] = 0; }   /* never used: keys are generated with explicit randomness */
}

void x25519_clamp(unsigned char sk[32])
{
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
}

void x25519_public_key(unsigned char pk[32], const unsigned char sk[32])
{
    crypto_scalarmult_base(pk, sk);
}

void x25519_agreement(unsigned char out[32], const unsigned char sk[32], const unsigned char pk[32])
{
    crypto_scalarmult(out, sk, pk);
}

void sha512_hash(unsigned char out[64], const unsigned char *m, unsigned long long n)
{
    crypto_hash(out, m, n);
}

int xeddsa_sign(unsigned char sig[64], const unsigned char sk[32],
                const unsigned char *m, unsigned long long n, const unsigned char random[64])
{
    u8 A[32], nonce[64], h[64], sign_bit;
    u8 *buf;
    i64 i, j, x[64];
    gf p[4];

    /* A = a*B in Edwards form; its sign bit travels in the signature. */
    scalarbase(p, sk);
    pack(A, p);
    sign_bit = A[31] & 0x80;

    /* nonce = SHA-512(0xFE || 0xFF*31 || a || M || Z) mod L */
    buf = (u8 *)malloc((size_t)(n + 128));
    if (!buf) return -1;
    buf[0] = 0xFE;
    FOR(i, 31) buf[1 + i] = 0xFF;
    FOR(i, 32) buf[32 + i] = sk[i];
    FOR(i, n) buf[64 + i] = m[i];
    FOR(i, 64) buf[64 + n + i] = random[i];
    crypto_hash(nonce, buf, n + 128);
    reduce(nonce);

    /* R = nonce*B */
    scalarbase(p, nonce);
    pack(sig, p);

    /* h = SHA-512(R || A || M) mod L */
    FOR(i, 32) buf[i] = sig[i];
    FOR(i, 32) buf[32 + i] = A[i];
    FOR(i, n) buf[64 + i] = m[i];
    crypto_hash(h, buf, n + 64);
    reduce(h);

    /* S = nonce + h*a mod L */
    FOR(i, 64) x[i] = 0;
    FOR(i, 32) x[i] = (u64)nonce[i];
    FOR(i, 32) FOR(j, 32) x[i + j] += h[i] * (u64)sk[j];
    modL(sig + 32, x);

    sig[63] &= 0x7F;
    sig[63] |= sign_bit;

    FOR(i, n + 128) buf[i] = 0;
    free(buf);
    return 0;
}

int xeddsa_verify(const unsigned char pk[32], const unsigned char *m, unsigned long long n,
                  const unsigned char sig[64])
{
    u8 ed_pk[32], sig2[64], t[32], h[64];
    u8 *buf;
    gf u, y, num, den, one;
    gf p[4], q[4];
    i64 i;

    /* Montgomery u -> Edwards y = (u - 1) / (u + 1) */
    unpack25519(u, pk);
    set25519(one, gf1);
    Z(num, u, one);
    A(den, u, one);
    inv25519(den, den);
    M(y, num, den);
    pack25519(ed_pk, y);
    ed_pk[31] &= 0x7F;
    ed_pk[31] |= sig[63] & 0x80;

    FOR(i, 64) sig2[i] = sig[i];
    sig2[63] &= 0x7F;

    if (unpackneg(q, ed_pk)) return -1;

    buf = (u8 *)malloc((size_t)(n + 64));
    if (!buf) return -1;
    FOR(i, 32) buf[i] = sig2[i];
    FOR(i, 32) buf[32 + i] = ed_pk[i];
    FOR(i, n) buf[64 + i] = m[i];
    crypto_hash(h, buf, n + 64);
    free(buf);
    reduce(h);

    /* R' = h*(-A) + S*B must equal R */
    scalarmult(p, q, h);
    scalarbase(q, sig2 + 32);
    add(p, q);
    pack(t, p);

    return crypto_verify_32(sig2, t) ? -1 : 0;
}
