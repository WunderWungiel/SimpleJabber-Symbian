// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// Session establishment (X3DH from a pre key bundle or an incoming pre key message) and the
// Double Ratchet cipher, following libsignal's SessionBuilder / SessionCipher /
// RatchetingSession step for step so the key schedule matches other OMEMO clients.
// Errors come back as false + a message rather than exceptions.
#ifndef SJ_SESSION_H
#define SJ_SESSION_H

#include "messages.h"
#include "store.h"

#include <QString>

namespace Signal {

/// A device's published keys, as parsed from its OMEMO bundle. Public keys are raw 32 bytes.
struct PreKeyBundle
{
    quint32 registrationId;
    quint32 deviceId;
    quint32 preKeyId;
    QByteArray preKeyPublic;          // may be empty (no one-time pre key)
    quint32 signedPreKeyId;
    QByteArray signedPreKeyPublic;
    QByteArray signedPreKeySignature;
    QByteArray identityKey;
    PreKeyBundle() : registrationId(0), deviceId(0), preKeyId(0), signedPreKeyId(0) {}
};

class SessionBuilder
{
public:
    SessionBuilder(Store *store, const Address &remote) : m_store(store), m_remote(remote) {}

    /// Alice: builds a session from the peer's bundle and stores it.
    bool processPreKeyBundle(const PreKeyBundle &bundle, QString *error);

    /// Bob: builds (or finds) the session an incoming pre key message initiates. Sets
    /// *consumedPreKeyId to the one-time pre key id to delete once decryption succeeded,
    /// or leaves *hasConsumedPreKey false. Does not store the record - the cipher does.
    bool processPreKeyMessage(SessionRecord &record, const PreKeySignalMessage &message,
                              bool *hasConsumedPreKey, quint32 *consumedPreKeyId, QString *error);

private:
    Store *m_store;
    Address m_remote;
};

class SessionCipher
{
public:
    SessionCipher(Store *store, const Address &remote) : m_store(store), m_remote(remote) {}

    /// Encrypts for the remote device. *isPreKeyMessage tells which envelope came out.
    bool encrypt(const QByteArray &plaintext, QByteArray *serialized, bool *isPreKeyMessage, QString *error);

    bool decryptPreKeyMessage(const PreKeySignalMessage &message, QByteArray *plaintext, QString *error);
    bool decryptMessage(const SignalMessage &message, QByteArray *plaintext, QString *error);

private:
    bool decryptWithRecord(SessionRecord &record, const SignalMessage &message, QByteArray *plaintext, QString *error);
    bool decryptWithState(SessionState &state, const SignalMessage &message, QByteArray *plaintext, QString *error);
    static bool chainKeyFor(SessionState &state, const QByteArray &theirEphemeral, ChainKey *out, QString *error);
    static bool messageKeysFor(SessionState &state, const QByteArray &theirEphemeral, ChainKey chainKey, quint32 counter,
                               MessageKeys *out, QString *error);

    Store *m_store;
    Address m_remote;
};

/// Symmetric helpers on the derived message keys (AES-256-CBC / PKCS#7, v3).
QByteArray aesCbcEncrypt(const QByteArray &key, const QByteArray &iv, const QByteArray &plaintext);
bool aesCbcDecrypt(const QByteArray &key, const QByteArray &iv, const QByteArray &ciphertext, QByteArray *plaintext);

} // namespace Signal

#endif
