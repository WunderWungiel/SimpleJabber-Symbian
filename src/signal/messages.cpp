// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "messages.h"
#include "curve.h"
#include "protobuf.h"
#include "../crypto/sha256.h"

namespace Signal {

namespace {
char versionByte(quint32 version)
{
    return char(((version & 0xf) << 4) | (CURRENT_VERSION & 0xf));
}
quint32 highBits(char b)
{
    return (quint32(uchar(b)) >> 4) & 0xf;
}
}

// -- SignalMessage ---------------------------------------------------------------------

QByteArray SignalMessage::computeMac(const QByteArray &senderIdentity, const QByteArray &receiverIdentity,
                                     const QByteArray &macKey, const QByteArray &data)
{
    QByteArray input;
    input.append(Curve::encodePublic(senderIdentity));
    input.append(Curve::encodePublic(receiverIdentity));
    input.append(data);
    unsigned char full[32];
    hmac_sha256(reinterpret_cast<const unsigned char *>(macKey.constData()), macKey.size(),
                reinterpret_cast<const unsigned char *>(input.constData()), input.size(), full);
    return QByteArray(reinterpret_cast<const char *>(full), MAC_LENGTH);
}

SignalMessage SignalMessage::create(quint32 version, const QByteArray &macKey, const QByteArray &senderRatchetKey,
                                    quint32 counter, quint32 previousCounter, const QByteArray &ciphertext,
                                    const QByteArray &senderIdentity, const QByteArray &receiverIdentity)
{
    SignalMessage m;
    m.m_version = version;
    m.m_ratchetKey = senderRatchetKey;
    m.m_counter = counter;
    m.m_previousCounter = previousCounter;
    m.m_ciphertext = ciphertext;

    ProtoWriter w;
    w.bytes(1, Curve::encodePublic(senderRatchetKey));
    w.varint(2, counter);
    w.varint(3, previousCounter);
    w.bytes(4, ciphertext);

    QByteArray data;
    data.append(versionByte(version));
    data.append(w.result());
    m.m_serialized = data + computeMac(senderIdentity, receiverIdentity, macKey, data);
    m.m_valid = true;
    return m;
}

SignalMessage SignalMessage::parse(const QByteArray &serialized)
{
    SignalMessage m;
    if (serialized.size() < 1 + int(MAC_LENGTH) + 1) return m;
    const quint32 version = highBits(serialized.at(0));
    if (version != CURRENT_VERSION) return m;   // v2 (legacy) and unknown versions are refused

    const QByteArray body = serialized.mid(1, serialized.size() - 1 - MAC_LENGTH);
    ProtoReader r(body);
    if (!r.ok() || !r.has(1) || !r.has(2) || !r.has(4)) return m;
    const QByteArray ratchet = Curve::decodePublic(r.bytes(1));
    if (ratchet.isEmpty()) return m;

    m.m_version = version;
    m.m_ratchetKey = ratchet;
    m.m_counter = quint32(r.varint(2));
    m.m_previousCounter = quint32(r.varint(3));
    m.m_ciphertext = r.bytes(4);
    m.m_serialized = serialized;
    m.m_valid = true;
    return m;
}

bool SignalMessage::verifyMac(const QByteArray &senderIdentity, const QByteArray &receiverIdentity, const QByteArray &macKey) const
{
    if (!m_valid || m_serialized.size() < int(MAC_LENGTH)) return false;
    const QByteArray data = m_serialized.left(m_serialized.size() - MAC_LENGTH);
    const QByteArray theirMac = m_serialized.right(MAC_LENGTH);
    const QByteArray ourMac = computeMac(senderIdentity, receiverIdentity, macKey, data);
    // Constant-time compare.
    uchar diff = 0;
    for (int i = 0; i < int(MAC_LENGTH); ++i) diff |= uchar(ourMac.at(i)) ^ uchar(theirMac.at(i));
    return diff == 0;
}

// -- PreKeySignalMessage ---------------------------------------------------------------

PreKeySignalMessage PreKeySignalMessage::create(quint32 version, quint32 registrationId, bool hasPreKeyId, quint32 preKeyId,
                                                quint32 signedPreKeyId, const QByteArray &baseKey, const QByteArray &identityKey,
                                                const SignalMessage &message)
{
    PreKeySignalMessage m;
    m.m_version = version;
    m.m_registrationId = registrationId;
    m.m_hasPreKeyId = hasPreKeyId;
    m.m_preKeyId = preKeyId;
    m.m_signedPreKeyId = signedPreKeyId;
    m.m_baseKey = baseKey;
    m.m_identityKey = identityKey;
    m.m_message = message;

    // Field order follows libsignal's builder so the bytes match other implementations
    // byte for byte (not required by protobuf, but it keeps captures comparable).
    ProtoWriter w;
    if (hasPreKeyId) w.varint(1, preKeyId);
    w.bytes(2, Curve::encodePublic(baseKey));
    w.bytes(3, Curve::encodePublic(identityKey));
    w.bytes(4, message.serialized());
    w.varint(5, registrationId);
    w.varint(6, signedPreKeyId);

    m.m_serialized.append(versionByte(version));
    m.m_serialized.append(w.result());
    m.m_valid = true;
    return m;
}

PreKeySignalMessage PreKeySignalMessage::parse(const QByteArray &serialized)
{
    PreKeySignalMessage m;
    if (serialized.size() < 2) return m;
    const quint32 version = highBits(serialized.at(0));
    if (version != CURRENT_VERSION) return m;

    ProtoReader r(serialized.mid(1));
    if (!r.ok() || !r.has(6) || !r.has(2) || !r.has(3) || !r.has(4)) return m;
    const QByteArray base = Curve::decodePublic(r.bytes(2));
    const QByteArray identity = Curve::decodePublic(r.bytes(3));
    if (base.isEmpty() || identity.isEmpty()) return m;
    const SignalMessage inner = SignalMessage::parse(r.bytes(4));
    if (!inner.isValid()) return m;

    m.m_version = version;
    m.m_registrationId = quint32(r.varint(5));
    m.m_hasPreKeyId = r.has(1);
    m.m_preKeyId = quint32(r.varint(1));
    m.m_signedPreKeyId = quint32(r.varint(6));
    m.m_baseKey = base;
    m.m_identityKey = identity;
    m.m_message = inner;
    m.m_serialized = serialized;
    m.m_valid = true;
    return m;
}

} // namespace Signal
