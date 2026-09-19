// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "store.h"
#include "messages.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>

namespace Signal {

FileStore::FileStore(const QString &baseDir)
    : m_base(baseDir), m_deviceId(0)
{
}

QString FileStore::hex(const QString &s)
{
    return QString::fromLatin1(s.toUtf8().toHex());
}

QString FileStore::preKeyPath(quint32 id) const { return m_base + QLatin1String("/prekey/") + QString::number(id) + QLatin1String(".dat"); }
QString FileStore::signedPreKeyPath(quint32 id) const { return m_base + QLatin1String("/signed/") + QString::number(id) + QLatin1String(".dat"); }
QString FileStore::sessionPath(const Address &a) const
{
    return m_base + QLatin1String("/session/") + hex(a.name) + QLatin1Char('_') + QString::number(a.deviceId) + QLatin1String(".dat");
}

QByteArray FileStore::readFile(const QString &path)
{
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) return QByteArray();
    return f.readAll();
}

bool FileStore::writeFile(const QString &path, const QByteArray &data)
{
    QDir().mkpath(QFileInfo(path).absolutePath());
    // Write to a temporary name and rename, so a crash mid-write cannot leave a truncated
    // session behind (which would break the ratchet).
    const QString tmp = path + QLatin1String(".tmp");
    QFile f(tmp);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    if (f.write(data) != data.size()) { f.close(); QFile::remove(tmp); return false; }
    f.close();
    QFile::remove(path);
    return QFile::rename(tmp, path);
}

QList<quint32> FileStore::numericIds(const QString &dir)
{
    QList<quint32> ids;
    const QStringList names = QDir(dir).entryList(QStringList() << QLatin1String("*.dat"), QDir::Files);
    for (int i = 0; i < names.size(); ++i) {
        bool ok = false;
        const quint32 id = names.at(i).left(names.at(i).size() - 4).toUInt(&ok);
        if (ok) ids.append(id);
    }
    return ids;
}

// -- own device --

bool FileStore::hasOwnDevice() const
{
    return QFile::exists(m_base + QLatin1String("/identity.dat")) && QFile::exists(m_base + QLatin1String("/device.txt"));
}

bool FileStore::loadOrCreateOwnDevice()
{
    if (hasOwnDevice()) {
        m_identity = IdentityKeyPair::deserialize(readFile(m_base + QLatin1String("/identity.dat")));
        m_deviceId = QString::fromLatin1(readFile(m_base + QLatin1String("/device.txt"))).trimmed().toUInt();
        if (m_identity.isValid() && m_deviceId != 0) return true;
    }
    const ECKeyPair kp = Curve::generateKeyPair();
    m_identity.publicKey = kp.publicKey;
    m_identity.privateKey = kp.privateKey;
    // The OMEMO device id doubles as the registration id: non-zero, fits 31 bits. libsignal
    // draws from [1, 16380]; a wider range makes a clash with another client of the same
    // account far less likely, and every OMEMO client accepts any positive integer.
    m_deviceId = (Curve::randomUInt() % 0x7ffffffe) + 1;
    return writeFile(m_base + QLatin1String("/identity.dat"), m_identity.serialize())
        && writeFile(m_base + QLatin1String("/device.txt"), QString::number(m_deviceId).toLatin1());
}

bool FileStore::saveIdentity(const QString &name, const QByteArray &identityKey)
{
    const QString path = m_base + QLatin1String("/identity/") + hex(name) + QLatin1String(".dat");
    const bool existed = QFile::exists(path);
    writeFile(path, identityKey);
    return existed;
}

QByteArray FileStore::loadIdentity(const QString &name) const
{
    return readFile(m_base + QLatin1String("/identity/") + hex(name) + QLatin1String(".dat"));
}

// -- pre keys --

bool FileStore::loadPreKey(quint32 id, PreKeyRecord *out) const
{
    const QByteArray data = readFile(preKeyPath(id));
    if (data.isEmpty()) return false;
    *out = PreKeyRecord::deserialize(data);
    return out->keyPair.isValid();
}

void FileStore::storePreKey(quint32 id, const PreKeyRecord &record) { writeFile(preKeyPath(id), record.serialize()); }
bool FileStore::containsPreKey(quint32 id) const { return QFile::exists(preKeyPath(id)); }
void FileStore::removePreKey(quint32 id) { QFile::remove(preKeyPath(id)); }
QList<quint32> FileStore::preKeyIds() const { return numericIds(m_base + QLatin1String("/prekey")); }

bool FileStore::loadSignedPreKey(quint32 id, SignedPreKeyRecord *out) const
{
    const QByteArray data = readFile(signedPreKeyPath(id));
    if (data.isEmpty()) return false;
    *out = SignedPreKeyRecord::deserialize(data);
    return out->keyPair.isValid();
}

void FileStore::storeSignedPreKey(quint32 id, const SignedPreKeyRecord &record) { writeFile(signedPreKeyPath(id), record.serialize()); }
bool FileStore::containsSignedPreKey(quint32 id) const { return QFile::exists(signedPreKeyPath(id)); }

// -- sessions --

SessionRecord FileStore::loadSession(const Address &address) const
{
    const QByteArray data = readFile(sessionPath(address));
    if (data.isEmpty()) return SessionRecord();
    bool ok = false;
    SessionRecord r = SessionRecord::deserialize(data, &ok);
    return ok ? r : SessionRecord();
}

void FileStore::storeSession(const Address &address, const SessionRecord &record)
{
    writeFile(sessionPath(address), record.serialize());
}

bool FileStore::containsSession(const Address &address) const
{
    if (!QFile::exists(sessionPath(address))) return false;
    // A session made by RECEIVING a pre key message has no sender chain yet but is still
    // usable for encryption, so only the version is checked (as JabberWP does).
    const SessionRecord r = loadSession(address);
    return !r.isFresh() && r.sessionState().sessionVersion() == CURRENT_VERSION;
}

QList<quint32> FileStore::subDeviceSessions(const QString &name) const
{
    QList<quint32> ids;
    const QString prefix = hex(name) + QLatin1Char('_');
    const QStringList names = QDir(m_base + QLatin1String("/session")).entryList(QStringList() << QLatin1String("*.dat"), QDir::Files);
    for (int i = 0; i < names.size(); ++i) {
        const QString &n = names.at(i);
        if (!n.startsWith(prefix)) continue;
        bool ok = false;
        const quint32 id = n.mid(prefix.size(), n.size() - prefix.size() - 4).toUInt(&ok);
        if (ok) ids.append(id);
    }
    return ids;
}

void FileStore::deleteSession(const Address &address) { QFile::remove(sessionPath(address)); }

void FileStore::clear()
{
    QDir dir(m_base);
    const char *subdirs[] = { "prekey", "signed", "session", "identity" };
    for (int d = 0; d < 4; ++d) {
        QDir sub(m_base + QLatin1Char('/') + QLatin1String(subdirs[d]));
        const QStringList files = sub.entryList(QDir::Files);
        for (int i = 0; i < files.size(); ++i) sub.remove(files.at(i));
        dir.rmdir(QLatin1String(subdirs[d]));
    }
    dir.remove(QLatin1String("identity.dat"));
    dir.remove(QLatin1String("device.txt"));
    m_identity = IdentityKeyPair();
    m_deviceId = 0;
}

} // namespace Signal
