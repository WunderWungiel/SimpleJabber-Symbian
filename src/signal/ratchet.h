// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// The Double Ratchet key schedule (HKDF v3 with libsignal's info strings):
//   root  --DH--> "WhisperRatchet"    -> new root key || chain key
//   chain --HMAC(0x02)--> next chain; --HMAC(0x01)--> "WhisperMessageKeys" -> cipher/mac/iv
#ifndef SJ_RATCHET_H
#define SJ_RATCHET_H

#include <QByteArray>
#include "curve.h"

namespace Signal {

struct MessageKeys
{
    QByteArray cipherKey;   // 32
    QByteArray macKey;      // 32
    QByteArray iv;          // 16
    quint32 counter;
    MessageKeys() : counter(0) {}
};

struct ChainKey
{
    QByteArray key;   // 32
    quint32 index;
    ChainKey() : index(0) {}
    ChainKey(const QByteArray &k, quint32 i) : key(k), index(i) {}

    ChainKey next() const;
    MessageKeys messageKeys() const;
};

struct RootKey
{
    QByteArray key;   // 32
    RootKey() {}
    explicit RootKey(const QByteArray &k) : key(k) {}

    /// One DH ratchet step: the new root key and the chain key for that direction.
    void createChain(const QByteArray &theirRatchetKey, const ECKeyPair &ourRatchetKey,
                     RootKey *newRoot, ChainKey *newChain) const;
};

namespace Kdf {
    /// HKDF-SHA256 with a 32-byte zero salt (libsignal's deriveSecrets without a salt).
    QByteArray deriveSecrets(const QByteArray &inputKeyMaterial, const QByteArray &info, int outputLength);
    QByteArray deriveSecrets(const QByteArray &inputKeyMaterial, const QByteArray &salt, const QByteArray &info, int outputLength);
    QByteArray hmacSha256(const QByteArray &key, const QByteArray &data);
    QByteArray sha256(const QByteArray &data);
}

} // namespace Signal

#endif
