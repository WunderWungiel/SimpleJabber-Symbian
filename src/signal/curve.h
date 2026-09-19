// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// The elliptic-curve layer of the Signal protocol on QByteArray: Curve25519 key pairs,
// agreement, XEdDSA signatures, and the 0x05-prefixed public key encoding libsignal uses
// everywhere on the wire (bundles, ratchet keys, identity keys).
#ifndef SJ_CURVE_H
#define SJ_CURVE_H

#include <QByteArray>

namespace Signal {

const char DJB_TYPE = 0x05;

struct ECKeyPair
{
    QByteArray publicKey;    // 32 raw bytes
    QByteArray privateKey;   // 32 raw bytes (clamped)

    bool isValid() const { return publicKey.size() == 32 && privateKey.size() == 32; }
};

namespace Curve {
    /// Cryptographically random bytes from the platform (Math::Random on Symbian).
    QByteArray randomBytes(int n);
    quint32 randomUInt();

    ECKeyPair generateKeyPair();

    /// 0x05 || 32 bytes - the encoding on the wire and in bundles.
    QByteArray encodePublic(const QByteArray &rawPublic);
    /// Reads a 0x05-prefixed key; returns an empty array for anything else.
    QByteArray decodePublic(const QByteArray &encoded);

    QByteArray agreement(const QByteArray &theirPublic, const QByteArray &ourPrivate);
    QByteArray sign(const QByteArray &privateKey, const QByteArray &message);
    bool verify(const QByteArray &publicKey, const QByteArray &message, const QByteArray &signature);
}

} // namespace Signal

#endif
