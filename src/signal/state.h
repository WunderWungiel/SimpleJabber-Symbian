// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// Session and key records. They mirror libsignal's SessionStructure / PreKeyRecord /
// SignedPreKeyRecord field for field, but are stored in the app's own QDataStream format:
// nothing else ever reads these files, so protobuf compatibility would buy nothing.
#ifndef SJ_STATE_H
#define SJ_STATE_H

#include "curve.h"
#include "ratchet.h"

#include <QByteArray>
#include <QList>

namespace Signal {

struct IdentityKeyPair
{
    QByteArray publicKey;    // raw 32
    QByteArray privateKey;   // raw 32
    bool isValid() const { return publicKey.size() == 32 && privateKey.size() == 32; }
    QByteArray serialize() const;
    static IdentityKeyPair deserialize(const QByteArray &data);
};

struct PreKeyRecord
{
    quint32 id;
    ECKeyPair keyPair;
    PreKeyRecord() : id(0) {}
    QByteArray serialize() const;
    static PreKeyRecord deserialize(const QByteArray &data);
};

struct SignedPreKeyRecord
{
    quint32 id;
    quint64 timestamp;
    ECKeyPair keyPair;
    QByteArray signature;
    SignedPreKeyRecord() : id(0), timestamp(0) {}
    QByteArray serialize() const;
    static SignedPreKeyRecord deserialize(const QByteArray &data);
};

struct StoredMessageKeys
{
    quint32 index;
    QByteArray cipherKey, macKey, iv;
};

struct Chain
{
    QByteArray senderRatchetKey;          // raw 32 public
    QByteArray senderRatchetKeyPrivate;   // raw 32, sender chain only
    ChainKey chainKey;
    QList<StoredMessageKeys> messageKeys; // receiver chains only: skipped keys
};

class SessionState
{
public:
    SessionState();

    quint32 sessionVersion() const { return m_sessionVersion == 0 ? 2 : m_sessionVersion; }
    void setSessionVersion(quint32 v) { m_sessionVersion = v; }

    QByteArray remoteIdentityKey() const { return m_remoteIdentity; }
    void setRemoteIdentityKey(const QByteArray &raw) { m_remoteIdentity = raw; }
    QByteArray localIdentityKey() const { return m_localIdentity; }
    void setLocalIdentityKey(const QByteArray &raw) { m_localIdentity = raw; }

    quint32 previousCounter() const { return m_previousCounter; }
    void setPreviousCounter(quint32 c) { m_previousCounter = c; }

    RootKey rootKey() const { return RootKey(m_rootKey); }
    void setRootKey(const RootKey &k) { m_rootKey = k.key; }

    // sender chain
    bool hasSenderChain() const { return m_hasSenderChain; }
    QByteArray senderRatchetKey() const { return m_senderChain.senderRatchetKey; }
    ECKeyPair senderRatchetKeyPair() const;
    ChainKey senderChainKey() const { return m_senderChain.chainKey; }
    void setSenderChain(const ECKeyPair &ratchetKey, const ChainKey &chainKey);
    void setSenderChainKey(const ChainKey &chainKey) { m_senderChain.chainKey = chainKey; }

    // receiver chains
    bool hasReceiverChain(const QByteArray &senderEphemeral) const { return receiverChainIndex(senderEphemeral) >= 0; }
    ChainKey receiverChainKey(const QByteArray &senderEphemeral) const;
    void addReceiverChain(const QByteArray &senderRatchetKey, const ChainKey &chainKey);
    void setReceiverChainKey(const QByteArray &senderEphemeral, const ChainKey &chainKey);
    bool hasMessageKeys(const QByteArray &senderEphemeral, quint32 counter) const;
    MessageKeys removeMessageKeys(const QByteArray &senderEphemeral, quint32 counter);
    void setMessageKeys(const QByteArray &senderEphemeral, const MessageKeys &keys);

    // pending pre key (Alice side until the first reply arrives)
    void setUnacknowledgedPreKeyMessage(bool hasPreKeyId, quint32 preKeyId, quint32 signedPreKeyId, const QByteArray &baseKey);
    bool hasUnacknowledgedPreKeyMessage() const { return m_hasPendingPreKey; }
    void clearUnacknowledgedPreKeyMessage() { m_hasPendingPreKey = false; }
    bool pendingHasPreKeyId() const { return m_pendingHasPreKeyId; }
    quint32 pendingPreKeyId() const { return m_pendingPreKeyId; }
    quint32 pendingSignedPreKeyId() const { return m_pendingSignedPreKeyId; }
    QByteArray pendingBaseKey() const { return m_pendingBaseKey; }

    quint32 remoteRegistrationId() const { return m_remoteRegistrationId; }
    void setRemoteRegistrationId(quint32 id) { m_remoteRegistrationId = id; }
    quint32 localRegistrationId() const { return m_localRegistrationId; }
    void setLocalRegistrationId(quint32 id) { m_localRegistrationId = id; }

    QByteArray aliceBaseKey() const { return m_aliceBaseKey; }
    void setAliceBaseKey(const QByteArray &raw) { m_aliceBaseKey = raw; }

    void serialize(QDataStream &out) const;
    bool deserialize(QDataStream &in);

private:
    int receiverChainIndex(const QByteArray &senderEphemeral) const;

    quint32 m_sessionVersion;
    QByteArray m_localIdentity, m_remoteIdentity;
    QByteArray m_rootKey;
    quint32 m_previousCounter;
    bool m_hasSenderChain;
    Chain m_senderChain;
    QList<Chain> m_receiverChains;
    bool m_hasPendingPreKey, m_pendingHasPreKeyId;
    quint32 m_pendingPreKeyId, m_pendingSignedPreKeyId;
    QByteArray m_pendingBaseKey;
    quint32 m_remoteRegistrationId, m_localRegistrationId;
    QByteArray m_aliceBaseKey;
};

class SessionRecord
{
public:
    SessionRecord() : m_fresh(true) {}

    bool isFresh() const { return m_fresh; }
    SessionState &sessionState() { return m_state; }
    const SessionState &sessionState() const { return m_state; }
    QList<SessionState> &previousStates() { return m_previous; }

    bool hasSessionState(quint32 version, const QByteArray &aliceBaseKey) const;
    void archiveCurrentState();
    void promoteState(const SessionState &promoted);
    void setState(const SessionState &s) { m_state = s; m_fresh = false; }

    QByteArray serialize() const;
    static SessionRecord deserialize(const QByteArray &data, bool *ok = 0);

private:
    SessionState m_state;
    QList<SessionState> m_previous;
    bool m_fresh;
};

} // namespace Signal

#endif
