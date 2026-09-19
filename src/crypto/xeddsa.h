/* SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
 * Curve25519 / XEdDSA primitives on TweetNaCl (see xeddsa.c). Plain C, no dependencies. */
#ifndef XEDDSA_H
#define XEDDSA_H

#ifdef __cplusplus
extern "C" {
#endif

/* Installs the random source TweetNaCl's randombytes() forwards to. */
void nacl_set_random_source(void (*source)(unsigned char *out, unsigned long long len));

/* Turns 32 random bytes into a Curve25519 private key (clears/sets the usual bits). */
void x25519_clamp(unsigned char sk[32]);
void x25519_public_key(unsigned char pk[32], const unsigned char sk[32]);
void x25519_agreement(unsigned char out[32], const unsigned char sk[32], const unsigned char pk[32]);

/* XEdDSA: sign with a Curve25519 private key; verify with the Curve25519 public key.
 * random is 64 bytes of fresh randomness. Returns 0 on success / valid signature. */
int xeddsa_sign(unsigned char sig[64], const unsigned char sk[32],
                const unsigned char *m, unsigned long long n, const unsigned char random[64]);
int xeddsa_verify(const unsigned char pk[32], const unsigned char *m, unsigned long long n,
                  const unsigned char sig[64]);

void sha512_hash(unsigned char out[64], const unsigned char *m, unsigned long long n);

#ifdef __cplusplus
}
#endif

#endif
