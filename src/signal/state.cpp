// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "state.h"

#include <QDataStream>

namespace Signal {

namespace {
const quint32 MAX_MESSAGE_KEYS = 2000;
const int MAX_RECEIVER_CHAINS = 5;
const int MAX_ARCHIVED_STATES = 40;
const quint32 RECORD_MAGIC = 0x534a5352;   // "SJSR"
const quint32 RECORD_VERSION = 1;
}

// -- key records -------------------------------------------------------------------------

QByteArray IdentityKeyPair::serialize() const
{
    QByteArray out;
    QDataStream s(&out, QIODevice::WriteOnly);
    s << quint32(1) << publicKey << privateKey;
    return out;
}

IdentityKeyPair IdentityKeyPair::deserialize(const QByteArray &data)
{
    IdentityKeyPair k;
    QDataStream s(data);
    quint32 v;
    s >> v >> k.publicKey >> k.privateKey;
    if (s.status() != QDataStream::Ok || v != 1) return IdentityKeyPair();
    return k;
}

QByteArray PreKeyRecord::serialize() const
{
    QByteArray out;
    QDataStream s(&out, QIODevice::WriteOnly);
    s << quint32(1) << id << keyPair.publicKey << keyPair.privateKey;
    return out;
}

PreKeyRecord PreKeyRecord::deserialize(const QByteArray &data)
{
    PreKeyRecord r;
    QDataStream s(data);
    quint32 v;
    s >> v >> r.id >> r.keyPair.publicKey >> r.keyPair.privateKey;
    if (s.status() != QDataStream::Ok || v != 1) return PreKeyRecord();
    return r;
}

QByteArray SignedPreKeyRecord::serialize() const
{
    QByteArray out;
    QDataStream s(&out, QIODevice::WriteOnly);
    s << quint32(1) << id << timestamp << keyPair.publicKey << keyPair.privateKey << signature;
    return out;
}

SignedPreKeyRecord SignedPreKeyRecord::deserialize(const QByteArray &data)
{
    SignedPreKeyRecord r;
    QDataStream s(data);
    quint32 v;
    s >> v >> r.id >> r.timestamp >> r.keyPair.publicKey >> r.keyPair.privateKey >> r.signature;
    if (s.status() != QDataStream::Ok || v != 1) return SignedPreKeyRecord();
    return r;
}

// -- SessionState ------------------------------------------------------------------------

SessionState::SessionState()
    : m_sessionVersion(0), m_previousCounter(0), m_hasSenderChain(false),
      m_hasPendingPreKey(false), m_pendingHasPreKeyId(false), m_pendingPreKeyId(0), m_pendingSignedPreKeyId(0),
      m_remoteRegistrationId(0), m_localRegistrationId(0)
{
}

ECKeyPair SessionState::senderRatchetKeyPair() const
{
    ECKeyPair kp;
    kp.publicKey = m_senderChain.senderRatchetKey;
    kp.privateKey = m_senderChain.senderRatchetKeyPrivate;
    return kp;
}

void SessionState::setSenderChain(const ECKeyPair &ratchetKey, const ChainKey &chainKey)
{
    m_senderChain.senderRatchetKey = ratchetKey.publicKey;
    m_senderChain.senderRatchetKeyPrivate = ratchetKey.privateKey;
    m_senderChain.chainKey = chainKey;
    m_senderChain.messageKeys.clear();
    m_hasSenderChain = true;
}

int SessionState::receiverChainIndex(const QByteArray &senderEphemeral) const
{
    for (int i = 0; i < m_receiverChains.size(); ++i)
        if (m_receiverChains.at(i).senderRatchetKey == senderEphemeral) return i;
    return -1;
}

ChainKey SessionState::receiverChainKey(const QByteArray &senderEphemeral) const
{
    const int i = receiverChainIndex(senderEphemeral);
    return i < 0 ? ChainKey() : m_receiverChains.at(i).chainKey;
}

void SessionState::addReceiverChain(const QByteArray &senderRatchetKey, const ChainKey &chainKey)
{
    Chain c;
    c.senderRatchetKey = senderRatchetKey;
    c.chainKey = chainKey;
    m_receiverChains.append(c);
    // libsignal keeps the five most recent receiver chains.
    while (m_receiverChains.size() > MAX_RECEIVER_CHAINS) m_receiverChains.removeFirst();
}

void SessionState::setReceiverChainKey(const QByteArray &senderEphemeral, const ChainKey &chainKey)
{
    const int i = receiverChainIndex(senderEphemeral);
    if (i >= 0) m_receiverChains[i].chainKey = chainKey;
}

bool SessionState::hasMessageKeys(const QByteArray &senderEphemeral, quint32 counter) const
{
    const int i = receiverChainIndex(senderEphemeral);
    if (i < 0) return false;
    const QList<StoredMessageKeys> &keys = m_receiverChains.at(i).messageKeys;
    for (int k = 0; k < keys.size(); ++k)
        if (keys.at(k).index == counter) return true;
    return false;
}

MessageKeys SessionState::removeMessageKeys(const QByteArray &senderEphemeral, quint32 counter)
{
    MessageKeys mk;
    const int i = receiverChainIndex(senderEphemeral);
    if (i < 0) return mk;
    QList<StoredMessageKeys> &keys = m_receiverChains[i].messageKeys;
    for (int k = 0; k < keys.size(); ++k) {
        if (keys.at(k).index == counter) {
            mk.cipherKey = keys.at(k).cipherKey;
            mk.macKey = keys.at(k).macKey;
            mk.iv = keys.at(k).iv;
            mk.counter = counter;
            keys.removeAt(k);
            break;
        }
    }
    return mk;
}

void SessionState::setMessageKeys(const QByteArray &senderEphemeral, const MessageKeys &keys)
{
    const int i = receiverChainIndex(senderEphemeral);
    if (i < 0) return;
    StoredMessageKeys s;
    s.index = keys.counter;
    s.cipherKey = keys.cipherKey;
    s.macKey = keys.macKey;
    s.iv = keys.iv;
    QList<StoredMessageKeys> &list = m_receiverChains[i].messageKeys;
    list.append(s);
    while (quint32(list.size()) > MAX_MESSAGE_KEYS) list.removeFirst();
}

void SessionState::setUnacknowledgedPreKeyMessage(bool hasPreKeyId, quint32 preKeyId, quint32 signedPreKeyId, const QByteArray &baseKey)
{
    m_hasPendingPreKey = true;
    m_pendingHasPreKeyId = hasPreKeyId;
    m_pendingPreKeyId = preKeyId;
    m_pendingSignedPreKeyId = signedPreKeyId;
    m_pendingBaseKey = baseKey;
}

static void writeChain(QDataStream &out, const Chain &c)
{
    out << c.senderRatchetKey << c.senderRatchetKeyPrivate << c.chainKey.key << c.chainKey.index;
    out << quint32(c.messageKeys.size());
    for (int i = 0; i < c.messageKeys.size(); ++i) {
        const StoredMessageKeys &m = c.messageKeys.at(i);
        out << m.index << m.cipherKey << m.macKey << m.iv;
    }
}

static bool readChain(QDataStream &in, Chain *c)
{
    quint32 n = 0;
    in >> c->senderRatchetKey >> c->senderRatchetKeyPrivate >> c->chainKey.key >> c->chainKey.index >> n;
    if (in.status() != QDataStream::Ok || n > MAX_MESSAGE_KEYS) return false;
    c->messageKeys.clear();
    for (quint32 i = 0; i < n; ++i) {
        StoredMessageKeys m;
        in >> m.index >> m.cipherKey >> m.macKey >> m.iv;
        c->messageKeys.append(m);
    }
    return in.status() == QDataStream::Ok;
}

void SessionState::serialize(QDataStream &out) const
{
    out << m_sessionVersion << m_localIdentity << m_remoteIdentity << m_rootKey << m_previousCounter;
    out << m_hasSenderChain;
    writeChain(out, m_senderChain);
    out << quint32(m_receiverChains.size());
    for (int i = 0; i < m_receiverChains.size(); ++i) writeChain(out, m_receiverChains.at(i));
    out << m_hasPendingPreKey << m_pendingHasPreKeyId << m_pendingPreKeyId << m_pendingSignedPreKeyId << m_pendingBaseKey;
    out << m_remoteRegistrationId << m_localRegistrationId << m_aliceBaseKey;
}

bool SessionState::deserialize(QDataStream &in)
{
    quint32 n = 0;
    in >> m_sessionVersion >> m_localIdentity >> m_remoteIdentity >> m_rootKey >> m_previousCounter;
    in >> m_hasSenderChain;
    if (!readChain(in, &m_senderChain)) return false;
    in >> n;
    if (in.status() != QDataStream::Ok || n > 100) return false;
    m_receiverChains.clear();
    for (quint32 i = 0; i < n; ++i) {
        Chain c;
        if (!readChain(in, &c)) return false;
        m_receiverChains.append(c);
    }
    in >> m_hasPendingPreKey >> m_pendingHasPreKeyId >> m_pendingPreKeyId >> m_pendingSignedPreKeyId >> m_pendingBaseKey;
    in >> m_remoteRegistrationId >> m_localRegistrationId >> m_aliceBaseKey;
    return in.status() == QDataStream::Ok;
}

// -- SessionRecord -----------------------------------------------------------------------

bool SessionRecord::hasSessionState(quint32 version, const QByteArray &aliceBaseKey) const
{
    if (m_state.sessionVersion() == version && m_state.aliceBaseKey() == aliceBaseKey) return true;
    for (int i = 0; i < m_previous.size(); ++i)
        if (m_previous.at(i).sessionVersion() == version && m_previous.at(i).aliceBaseKey() == aliceBaseKey) return true;
    return false;
}

void SessionRecord::archiveCurrentState()
{
    promoteState(SessionState());
}

void SessionRecord::promoteState(const SessionState &promoted)
{
    m_previous.prepend(m_state);
    m_state = promoted;
    while (m_previous.size() > MAX_ARCHIVED_STATES) m_previous.removeLast();
    m_fresh = false;
}

QByteArray SessionRecord::serialize() const
{
    QByteArray out;
    QDataStream s(&out, QIODevice::WriteOnly);
    s << RECORD_MAGIC << RECORD_VERSION;
    m_state.serialize(s);
    s << quint32(m_previous.size());
    for (int i = 0; i < m_previous.size(); ++i) m_previous.at(i).serialize(s);
    return out;
}

SessionRecord SessionRecord::deserialize(const QByteArray &data, bool *ok)
{
    SessionRecord r;
    QDataStream s(data);
    quint32 magic = 0, version = 0, n = 0;
    s >> magic >> version;
    bool good = magic == RECORD_MAGIC && version == RECORD_VERSION && r.m_state.deserialize(s);
    if (good) {
        s >> n;
        good = s.status() == QDataStream::Ok && n <= quint32(MAX_ARCHIVED_STATES);
        for (quint32 i = 0; good && i < n; ++i) {
            SessionState prev;
            good = prev.deserialize(s);
            if (good) r.m_previous.append(prev);
        }
    }
    if (ok) *ok = good;
    if (!good) return SessionRecord();
    r.m_fresh = false;
    return r;
}

} // namespace Signal
