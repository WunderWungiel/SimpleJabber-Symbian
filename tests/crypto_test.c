/* SimpleJabber - crypto self-test against published vectors. Build and run on the desktop:
 *   gcc -O2 -I../src/crypto crypto_test.c ../src/crypto/xeddsa.c ../src/crypto/sha256.c ../src/crypto/aes.c -o crypto_test
 * Vectors: FIPS 180-4 / RFC 4231 / RFC 5869 / FIPS 197 / NIST GCM spec / RFC 7748 / RFC 8032 /
 * libsignal-protocol-c tests/test_curve25519.c (agreement and XEdDSA signature). */
#include "xeddsa.h"
#include "sha256.h"
#include "aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void unhex(const char *hex, unsigned char *out, int *len)
{
    int i, n = (int)strlen(hex) / 2;
    for (i = 0; i < n; ++i) {
        unsigned int b;
        sscanf(hex + 2 * i, "%2x", &b);
        out[i] = (unsigned char)b;
    }
    if (len) *len = n;
}

static void check(const char *name, const unsigned char *got, const char *expectedHex, int len)
{
    unsigned char exp[256];
    unhex(expectedHex, exp, 0);
    if (memcmp(got, exp, len) == 0) {
        printf("ok   %s\n", name);
    } else {
        int i;
        printf("FAIL %s\n     got ", name);
        for (i = 0; i < len; ++i) printf("%02x", got[i]);
        printf("\n     exp %s\n", expectedHex);
        ++failures;
    }
}

static void check_int(const char *name, int got, int expected)
{
    if (got == expected) printf("ok   %s\n", name);
    else { printf("FAIL %s: got %d expected %d\n", name, got, expected); ++failures; }
}

static void fake_random(unsigned char *out, unsigned long long len)
{
    unsigned long long i;
    for (i = 0; i < len; ++i) out[i] = (unsigned char)(rand() & 0xff);
}

int main(void)
{
    unsigned char out[128], key[64], iv[16], pt[64], ct[80], tag[16], tmp[80];
    int n, i;
    aes_ctx aes;
    aes_gcm_ctx gcm;

    nacl_set_random_source(fake_random);

    /* SHA-256 */
    sha256((const unsigned char *)"abc", 3, out);
    check("sha256(abc)", out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32);
    sha256((const unsigned char *)"", 0, out);
    check("sha256(empty)", out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32);
    {
        /* 1,000,000 x 'a' exercises the block/pad paths */
        unsigned char *big = (unsigned char *)malloc(1000000);
        memset(big, 'a', 1000000);
        sha256(big, 1000000, out);
        free(big);
        check("sha256(a*1e6)", out, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", 32);
    }

    /* HMAC-SHA256, RFC 4231 test case 2 */
    hmac_sha256((const unsigned char *)"Jefe", 4, (const unsigned char *)"what do ya want for nothing?", 28, out);
    check("hmac rfc4231 tc2", out, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32);
    /* test case 3: key 0xaa*20, data 0xdd*50 */
    memset(key, 0xaa, 20); memset(tmp, 0xdd, 50);
    hmac_sha256(key, 20, tmp, 50, out);
    check("hmac rfc4231 tc3", out, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", 32);

    /* HKDF-SHA256, RFC 5869 test case 1 */
    memset(key, 0x0b, 22);
    unhex("000102030405060708090a0b0c", iv, 0);
    unhex("f0f1f2f3f4f5f6f7f8f9", tmp, 0);
    hkdf_sha256(iv, 13, key, 22, tmp, 10, out, 42);
    check("hkdf rfc5869 tc1", out, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", 42);
    /* HKDF with an all-zero 32-byte salt, as Signal uses it (extract with salt = 0^32) */

    /* AES-128 / AES-256 block, FIPS 197 C.1 / C.3 */
    unhex("000102030405060708090a0b0c0d0e0f", key, 0);
    unhex("00112233445566778899aabbccddeeff", pt, 0);
    aes_set_key(&aes, key, 16);
    aes_encrypt_block(&aes, pt, out);
    check("aes128 encrypt", out, "69c4e0d86a7b0430d8cdb78070b4c55a", 16);
    aes_decrypt_block(&aes, out, tmp);
    check("aes128 decrypt", tmp, "00112233445566778899aabbccddeeff", 16);
    unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key, 0);
    aes_set_key(&aes, key, 32);
    aes_encrypt_block(&aes, pt, out);
    check("aes256 encrypt", out, "8ea2b7ca516745bfeafc49904b496089", 16);
    aes_decrypt_block(&aes, out, tmp);
    check("aes256 decrypt", tmp, "00112233445566778899aabbccddeeff", 16);

    /* AES-256-CBC PKCS#7 round trip, NIST SP 800-38A F.2.5 first block check */
    unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key, 0);
    unhex("000102030405060708090a0b0c0d0e0f", iv, 0);
    unhex("6bc1bee22e409f96e93d7e117393172a", pt, 0);
    aes_set_key(&aes, key, 32);
    n = (int)aes_cbc_pkcs7_encrypt(&aes, iv, pt, 16, ct);
    check_int("cbc length (16 -> 32)", n, 32);
    check("cbc first block sp800-38a", ct, "f58c4c04d6e5f1ba779eabfb5f7bfbd6", 16);
    n = (int)aes_cbc_pkcs7_decrypt(&aes, iv, ct, 32, tmp);
    check_int("cbc decrypt length", n, 16);
    check("cbc decrypt data", tmp, "6bc1bee22e409f96e93d7e117393172a", 16);
    n = (int)aes_cbc_pkcs7_encrypt(&aes, iv, pt, 5, ct);
    n = (int)aes_cbc_pkcs7_decrypt(&aes, iv, ct, (unsigned long)n, tmp);
    check_int("cbc partial block round trip", n, 5);
    ct[3] ^= 1;
    check_int("cbc corrupted padding rejected", (int)(aes_cbc_pkcs7_decrypt(&aes, iv, ct, 16, tmp) < 0), 1);

    /* AES-GCM, NIST GCM spec test cases 1, 2, 14 and 4 (with AAD) */
    memset(key, 0, 32); memset(iv, 0, 12); memset(pt, 0, 16);
    aes_gcm_set_key(&gcm, key, 16);
    aes_gcm_encrypt(&gcm, iv, 0, 0, pt, 0, ct, tag);
    check("gcm tc1 tag", tag, "58e2fccefa7e3061367f1d57a4e7455a", 16);
    aes_gcm_encrypt(&gcm, iv, 0, 0, pt, 16, ct, tag);
    check("gcm tc2 ct", ct, "0388dace60b6a392f328c2b971b2fe78", 16);
    check("gcm tc2 tag", tag, "ab6e47d42cec13bdf53a67b21257bddf", 16);
    aes_gcm_set_key(&gcm, key, 32);
    aes_gcm_encrypt(&gcm, iv, 0, 0, pt, 16, ct, tag);
    check("gcm tc14 (aes256) ct", ct, "cea7403d4d606b6e074ec5d3baf39d18", 16);
    check("gcm tc14 tag", tag, "d0d1c8a799996bf0265b98b5d48ab919", 16);
    {
        unsigned char p4[60], a4[20], c4[60];
        unhex("feffe9928665731c6d6a8f9467308308", key, 0);
        unhex("cafebabefacedbaddecaf888", iv, 0);
        unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", p4, 0);
        unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", a4, 0);
        aes_gcm_set_key(&gcm, key, 16);
        aes_gcm_encrypt(&gcm, iv, a4, 20, p4, 60, c4, tag);
        check("gcm tc4 ct", c4, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", 60);
        check("gcm tc4 tag", tag, "5bc94fbc3221a5db94fae95ae7121a47", 16);
        check_int("gcm tc4 decrypt ok", aes_gcm_decrypt(&gcm, iv, a4, 20, c4, 60, tmp, tag), 0);
        check("gcm tc4 plaintext", tmp, "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", 60);
        tag[0] ^= 1;
        check_int("gcm bad tag rejected", aes_gcm_decrypt(&gcm, iv, a4, 20, c4, 60, tmp, tag), -1);
    }

    /* X25519, RFC 7748 section 6.1 */
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", key, 0);
    x25519_public_key(out, key);
    check("x25519 alice public", out, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", 32);
    unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", tmp, 0);
    x25519_agreement(out, key, tmp);
    check("x25519 shared secret", out, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", 32);

    /* libsignal agreement vector */
    unhex("c806439dc9d2c476ffed8f2580c0888d58ab406bf7ae3698879021b96bb4bf59", key, 0);
    unhex("653614993d2b15ee9e5fd3d86ce719ef4ec1daae1886a87b3f5fa9565a27a22f", tmp, 0);
    x25519_agreement(out, key, tmp);
    check("libsignal agreement", out, "325f239328941ced6e673b86ba41017448e99b649a9c3806c1dd7ca4c477e629", 32);
    x25519_public_key(out, key);
    check("libsignal alice public", out, "1bb75966f2e93a3691dfff942bb2a466a1c08b8d78ca3f4d6df8b8bfa2e4ee28", 32);

    /* XEdDSA: libsignal's reference signature verifies with our verifier */
    {
        unsigned char sk[32], pk[32], msg[33], sig[64], sig2[64], rnd[64], pk2[32];
        unhex("c097248412e58bf05df487968205132794178e367637f5818f81e0e6ce73e865", sk, 0);
        unhex("ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64", pk, 0);
        unhex("05edce9d9c415ca78cb7252e72c2c4a554d3eb29485a0e1d503118d1a82d99fb4a", msg, 0);
        unhex("5de88ca9a89b4a115da79109c67c9c7464a3e4180274f1cb8c63c2984e286dfbede82deb9dcd9fae0bfbb821569b3d9001bd8130cd11d486cef047bd60b86e88", sig, 0);
        x25519_public_key(pk2, sk);
        check("xeddsa vector: public key derives", pk2, "ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64", 32);
        check_int("xeddsa verify libsignal signature", xeddsa_verify(pk, msg, 33, sig), 0);
        for (i = 0; i < 64; ++i) {
            memcpy(sig2, sig, 64);
            sig2[i] ^= 1;
            if (xeddsa_verify(pk, msg, 33, sig2) == 0) { printf("FAIL tampered signature byte %d accepted\n", i); ++failures; }
        }
        printf("ok   xeddsa tampered signatures rejected\n");
        msg[5] ^= 1;
        check_int("xeddsa tampered message rejected", xeddsa_verify(pk, msg, 33, sig), -1);
        msg[5] ^= 1;

        /* our own signatures verify, with the sign bit both ways over many keys */
        {
            int signbits[2] = {0, 0};
            for (i = 0; i < 40; ++i) {
                fake_random(sk, 32); x25519_clamp(sk);
                x25519_public_key(pk, sk);
                fake_random(rnd, 64);
                fake_random(msg, 33);
                if (xeddsa_sign(sig, sk, msg, 33, rnd) != 0 || xeddsa_verify(pk, msg, 33, sig) != 0) { printf("FAIL own sign/verify #%d\n", i); ++failures; }
                signbits[(sig[63] >> 7) & 1] = 1;
                msg[0] ^= 1;
                if (xeddsa_verify(pk, msg, 33, sig) == 0) { printf("FAIL own signature accepted for altered message #%d\n", i); ++failures; }
            }
            check_int("xeddsa own signatures round trip (both sign bits seen)", signbits[0] && signbits[1], 1);
        }
    }

    printf("%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
