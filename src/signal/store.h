// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// The protocol store: identity, pre keys, signed pre keys and sessions, and a file-backed
// implementation laid out like JabberWP's OmemoStorage (one directory per account, one file
// per record) under the app's private data folder.
#ifndef SJ_STORE_H
#define SJ_STORE_H

#include "state.h"

#include <QHash>
#include <QList>
#include <QString>

namespace Signal {

struct Address
{
    QString name;      // bare JID
    quint32 deviceId;
    Address() : deviceId(0) {}
    Address(const QString &n, quint32 d) : name(n), deviceId(d) {}
    QString toString() const { return name + QLatin1Char(':') + QString::number(deviceId); }
};

class Store
{
public:
    virtual ~Store() {}

    virtual IdentityKeyPair identityKeyPair() const = 0;
    virtual quint32 localRegistrationId() const = 0;
    /// Records the identity a peer presented; returns true if one was already on file.
    virtual bool saveIdentity(const QString &name, const QByteArray &identityKey) = 0;
    /// Blind trust (XEP-0384): every identity is accepted; the UI shows fingerprints.
    virtual bool isTrustedIdentity(const QString &name, const QByteArray &identityKey) { Q_UNUSED(name); Q_UNUSED(identityKey); return true; }

    virtual bool loadPreKey(quint32 id, PreKeyRecord *out) const = 0;
    virtual void storePreKey(quint32 id, const PreKeyRecord &record) = 0;
    virtual bool containsPreKey(quint32 id) const = 0;
    virtual void removePreKey(quint32 id) = 0;
    virtual QList<quint32> preKeyIds() const = 0;

    virtual bool loadSignedPreKey(quint32 id, SignedPreKeyRecord *out) const = 0;
    virtual void storeSignedPreKey(quint32 id, const SignedPreKeyRecord &record) = 0;
    virtual bool containsSignedPreKey(quint32 id) const = 0;

    virtual SessionRecord loadSession(const Address &address) const = 0;
    virtual void storeSession(const Address &address, const SessionRecord &record) = 0;
    virtual bool containsSession(const Address &address) const = 0;
    virtual QList<quint32> subDeviceSessions(const QString &name) const = 0;
    virtual void deleteSession(const Address &address) = 0;
};

class FileStore : public Store
{
public:
    /// baseDir: the account's OMEMO directory (created on demand).
    explicit FileStore(const QString &baseDir);

    /// Loads the identity and device id, generating both on first use.
    bool loadOrCreateOwnDevice();
    bool hasOwnDevice() const;
    quint32 deviceId() const { return m_deviceId; }

    IdentityKeyPair identityKeyPair() const { return m_identity; }
    quint32 localRegistrationId() const { return m_deviceId; }
    bool saveIdentity(const QString &name, const QByteArray &identityKey);
    /// The identity on file for a peer, or empty.
    QByteArray loadIdentity(const QString &name) const;

    bool loadPreKey(quint32 id, PreKeyRecord *out) const;
    void storePreKey(quint32 id, const PreKeyRecord &record);
    bool containsPreKey(quint32 id) const;
    void removePreKey(quint32 id);
    QList<quint32> preKeyIds() const;

    bool loadSignedPreKey(quint32 id, SignedPreKeyRecord *out) const;
    void storeSignedPreKey(quint32 id, const SignedPreKeyRecord &record);
    bool containsSignedPreKey(quint32 id) const;

    SessionRecord loadSession(const Address &address) const;
    void storeSession(const Address &address, const SessionRecord &record);
    bool containsSession(const Address &address) const;
    QList<quint32> subDeviceSessions(const QString &name) const;
    void deleteSession(const Address &address);

    /// Wipes everything (a new identity is generated on the next loadOrCreateOwnDevice).
    void clear();

private:
    static QString hex(const QString &s);
    QString preKeyPath(quint32 id) const;
    QString signedPreKeyPath(quint32 id) const;
    QString sessionPath(const Address &a) const;
    static QByteArray readFile(const QString &path);
    static bool writeFile(const QString &path, const QByteArray &data);
    static QList<quint32> numericIds(const QString &dir);

    QString m_base;
    IdentityKeyPair m_identity;
    quint32 m_deviceId;
};

} // namespace Signal

#endif
