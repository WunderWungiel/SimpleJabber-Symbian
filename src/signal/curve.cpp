// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "curve.h"
#include "../crypto/xeddsa.h"

#include <QDateTime>
#include <QCoreApplication>
#include <QUuid>

#ifdef Q_OS_SYMBIAN
#include <e32math.h>
#else
#include <stdlib.h>
#ifdef Q_OS_WIN
#include <windows.h>
#include <wincrypt.h>
#endif
#endif

namespace Signal {
namespace Curve {

QByteArray randomBytes(int n)
{
    QByteArray out(n, 0);
#ifdef Q_OS_SYMBIAN
    // The kernel's random pool (hardware-seeded on Symbian^3).
    int i = 0;
    while (i < n) {
        TUint32 r = Math::Random();
        for (int k = 0; k < 4 && i < n; ++k, ++i) out[i] = char((r >> (8 * k)) & 0xff);
    }
#elif defined(Q_OS_WIN)
    HCRYPTPROV prov = 0;
    bool ok = false;
    if (CryptAcquireContextW(&prov, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        ok = CryptGenRandom(prov, DWORD(n), reinterpret_cast<BYTE *>(out.data())) != 0;
        CryptReleaseContext(prov, 0);
    }
    if (!ok) {
        // Should never happen on Windows; a loud fallback rather than a silent weak one.
        qFatal("CryptGenRandom failed");
    }
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(out.data(), 1, n, f) != size_t(n)) qFatal("no /dev/urandom");
    if (f) fclose(f);
#endif
    return out;
}

quint32 randomUInt()
{
    const QByteArray b = randomBytes(4);
    return (quint32(uchar(b[0])) << 24) | (quint32(uchar(b[1])) << 16) | (quint32(uchar(b[2])) << 8) | quint32(uchar(b[3]));
}

ECKeyPair generateKeyPair()
{
    ECKeyPair kp;
    kp.privateKey = randomBytes(32);
    x25519_clamp(reinterpret_cast<unsigned char *>(kp.privateKey.data()));
    kp.publicKey.resize(32);
    x25519_public_key(reinterpret_cast<unsigned char *>(kp.publicKey.data()),
                      reinterpret_cast<const unsigned char *>(kp.privateKey.constData()));
    return kp;
}

QByteArray encodePublic(const QByteArray &rawPublic)
{
    QByteArray out;
    out.append(DJB_TYPE);
    out.append(rawPublic);
    return out;
}

QByteArray decodePublic(const QByteArray &encoded)
{
    if (encoded.size() != 33 || encoded.at(0) != DJB_TYPE) return QByteArray();
    return encoded.mid(1);
}

QByteArray agreement(const QByteArray &theirPublic, const QByteArray &ourPrivate)
{
    if (theirPublic.size() != 32 || ourPrivate.size() != 32) return QByteArray();
    QByteArray out(32, 0);
    x25519_agreement(reinterpret_cast<unsigned char *>(out.data()),
                     reinterpret_cast<const unsigned char *>(ourPrivate.constData()),
                     reinterpret_cast<const unsigned char *>(theirPublic.constData()));
    return out;
}

QByteArray sign(const QByteArray &privateKey, const QByteArray &message)
{
    if (privateKey.size() != 32) return QByteArray();
    const QByteArray random = randomBytes(64);
    QByteArray sig(64, 0);
    if (xeddsa_sign(reinterpret_cast<unsigned char *>(sig.data()),
                    reinterpret_cast<const unsigned char *>(privateKey.constData()),
                    reinterpret_cast<const unsigned char *>(message.constData()), message.size(),
                    reinterpret_cast<const unsigned char *>(random.constData())) != 0)
        return QByteArray();
    return sig;
}

bool verify(const QByteArray &publicKey, const QByteArray &message, const QByteArray &signature)
{
    if (publicKey.size() != 32 || signature.size() != 64) return false;
    return xeddsa_verify(reinterpret_cast<const unsigned char *>(publicKey.constData()),
                         reinterpret_cast<const unsigned char *>(message.constData()), message.size(),
                         reinterpret_cast<const unsigned char *>(signature.constData())) == 0;
}

} // namespace Curve
} // namespace Signal
