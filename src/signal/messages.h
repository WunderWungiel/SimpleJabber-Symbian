// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// The two ciphertext messages of the Signal protocol as OMEMO uses them, in libsignal's
// exact wire format:
//   SignalMessage       = version byte (0x33) || protobuf{ratchetKey=1, counter=2,
//                         previousCounter=3, ciphertext=4} || 8-byte HMAC-SHA256 truncation
//   PreKeySignalMessage = version byte (0x33) || protobuf{preKeyId=1, baseKey=2,
//                         identityKey=3, message=4, registrationId=5, signedPreKeyId=6}
// The MAC covers sender identity || receiver identity || version || message (v3).
#ifndef SJ_MESSAGES_H
#define SJ_MESSAGES_H

#include <QByteArray>

namespace Signal {

const quint32 CURRENT_VERSION = 3;
const quint32 MAC_LENGTH = 8;

class SignalMessage
{
public:
    SignalMessage() : m_version(0), m_counter(0), m_previousCounter(0), m_valid(false) {}

    /// Builds and MACs a new message. senderRatchetKey is a raw 32-byte public key;
    /// identity keys are raw 32-byte public keys.
    static SignalMessage create(quint32 version, const QByteArray &macKey, const QByteArray &senderRatchetKey,
                                quint32 counter, quint32 previousCounter, const QByteArray &ciphertext,
                                const QByteArray &senderIdentity, const QByteArray &receiverIdentity);
    /// Parses the wire form; isValid() tells whether it was well-formed and version 3.
    static SignalMessage parse(const QByteArray &serialized);

    bool isValid() const { return m_valid; }
    quint32 version() const { return m_version; }
    QByteArray senderRatchetKey() const { return m_ratchetKey; }
    quint32 counter() const { return m_counter; }
    quint32 previousCounter() const { return m_previousCounter; }
    QByteArray body() const { return m_ciphertext; }
    QByteArray serialized() const { return m_serialized; }

    bool verifyMac(const QByteArray &senderIdentity, const QByteArray &receiverIdentity, const QByteArray &macKey) const;

private:
    static QByteArray computeMac(const QByteArray &senderIdentity, const QByteArray &receiverIdentity,
                                 const QByteArray &macKey, const QByteArray &data);
    quint32 m_version;
    QByteArray m_ratchetKey;
    quint32 m_counter;
    quint32 m_previousCounter;
    QByteArray m_ciphertext;
    QByteArray m_serialized;
    bool m_valid;
};

class PreKeySignalMessage
{
public:
    PreKeySignalMessage() : m_version(0), m_registrationId(0), m_preKeyId(0), m_hasPreKeyId(false), m_signedPreKeyId(0), m_valid(false) {}

    static PreKeySignalMessage create(quint32 version, quint32 registrationId, bool hasPreKeyId, quint32 preKeyId,
                                      quint32 signedPreKeyId, const QByteArray &baseKey, const QByteArray &identityKey,
                                      const SignalMessage &message);
    static PreKeySignalMessage parse(const QByteArray &serialized);

    bool isValid() const { return m_valid; }
    quint32 version() const { return m_version; }
    quint32 registrationId() const { return m_registrationId; }
    bool hasPreKeyId() const { return m_hasPreKeyId; }
    quint32 preKeyId() const { return m_preKeyId; }
    quint32 signedPreKeyId() const { return m_signedPreKeyId; }
    QByteArray baseKey() const { return m_baseKey; }          // raw 32 bytes
    QByteArray identityKey() const { return m_identityKey; }  // raw 32 bytes
    const SignalMessage &message() const { return m_message; }
    QByteArray serialized() const { return m_serialized; }

private:
    quint32 m_version;
    quint32 m_registrationId;
    quint32 m_preKeyId;
    bool m_hasPreKeyId;
    quint32 m_signedPreKeyId;
    QByteArray m_baseKey;
    QByteArray m_identityKey;
    SignalMessage m_message;
    QByteArray m_serialized;
    bool m_valid;
};

} // namespace Signal

#endif
