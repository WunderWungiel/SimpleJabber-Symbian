// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "ratchet.h"
#include "../crypto/sha256.h"

namespace Signal {

namespace Kdf {

QByteArray hmacSha256(const QByteArray &key, const QByteArray &data)
{
    unsigned char out[32];
    hmac_sha256(reinterpret_cast<const unsigned char *>(key.constData()), key.size(),
                reinterpret_cast<const unsigned char *>(data.constData()), data.size(), out);
    return QByteArray(reinterpret_cast<const char *>(out), 32);
}

QByteArray sha256(const QByteArray &data)
{
    unsigned char out[32];
    ::sha256(reinterpret_cast<const unsigned char *>(data.constData()), data.size(), out);
    return QByteArray(reinterpret_cast<const char *>(out), 32);
}

QByteArray deriveSecrets(const QByteArray &ikm, const QByteArray &salt, const QByteArray &info, int outputLength)
{
    QByteArray out(outputLength, 0);
    hkdf_sha256(reinterpret_cast<const unsigned char *>(salt.constData()), salt.size(),
                reinterpret_cast<const unsigned char *>(ikm.constData()), ikm.size(),
                reinterpret_cast<const unsigned char *>(info.constData()), info.size(),
                reinterpret_cast<unsigned char *>(out.data()), outputLength);
    return out;
}

QByteArray deriveSecrets(const QByteArray &ikm, const QByteArray &info, int outputLength)
{
    return deriveSecrets(ikm, QByteArray(32, 0), info, outputLength);
}

} // namespace Kdf

ChainKey ChainKey::next() const
{
    return ChainKey(Kdf::hmacSha256(key, QByteArray(1, 0x02)), index + 1);
}

MessageKeys ChainKey::messageKeys() const
{
    const QByteArray input = Kdf::hmacSha256(key, QByteArray(1, 0x01));
    const QByteArray material = Kdf::deriveSecrets(input, QByteArray("WhisperMessageKeys"), 80);
    MessageKeys mk;
    mk.cipherKey = material.mid(0, 32);
    mk.macKey = material.mid(32, 32);
    mk.iv = material.mid(64, 16);
    mk.counter = index;
    return mk;
}

void RootKey::createChain(const QByteArray &theirRatchetKey, const ECKeyPair &ourRatchetKey,
                          RootKey *newRoot, ChainKey *newChain) const
{
    const QByteArray shared = Curve::agreement(theirRatchetKey, ourRatchetKey.privateKey);
    const QByteArray derived = Kdf::deriveSecrets(shared, key, QByteArray("WhisperRatchet"), 64);
    *newRoot = RootKey(derived.mid(0, 32));
    *newChain = ChainKey(derived.mid(32, 32), 0);
}

} // namespace Signal
