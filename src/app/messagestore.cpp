// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "messagestore.h"

#include <QDataStream>
#include <QDir>
#include <QFile>

namespace {
const quint32 MAGIC = 0x534a4d53;   // "SJMS"
const quint32 VERSION = 1;
const int MAX_PER_CHAT = 500;
const int MAX_AGE_DAYS = 183;
}

MessageStore::MessageStore(const QString &dir)
    : m_dir(dir)
{
}

QString MessageStore::pathFor(const QString &bareJid) const
{
    return m_dir + QLatin1Char('/') + QString::fromLatin1(bareJid.toLower().toUtf8().toHex()) + QLatin1String(".dat");
}

QList<XmppMessage> MessageStore::load(const QString &bareJid) const
{
    QList<XmppMessage> out;
    QFile f(pathFor(bareJid));
    if (!f.open(QIODevice::ReadOnly)) return out;
    QDataStream s(&f);
    quint32 magic = 0, version = 0, count = 0;
    s >> magic >> version >> count;
    if (magic != MAGIC || version != VERSION || count > 100000) return out;
    for (quint32 i = 0; i < count && s.status() == QDataStream::Ok; ++i) {
        XmppMessage m;
        m.contactJid = bareJid;
        s >> m.id >> m.body >> m.outgoing >> m.encrypted >> m.timestamp;
        if (s.status() == QDataStream::Ok) out.append(m);
    }
    return out;
}

void MessageStore::save(const QString &bareJid, QList<XmppMessage> messages) const
{
    trim(messages);
    QDir().mkpath(m_dir);
    const QString path = pathFor(bareJid);
    QFile f(path + QLatin1String(".tmp"));
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return;
    QDataStream s(&f);
    s << MAGIC << VERSION << quint32(messages.size());
    for (int i = 0; i < messages.size(); ++i) {
        const XmppMessage &m = messages.at(i);
        s << m.id << m.body << m.outgoing << m.encrypted << m.timestamp;
    }
    f.close();
    QFile::remove(path);
    QFile::rename(path + QLatin1String(".tmp"), path);
}

void MessageStore::trim(QList<XmppMessage> &messages)
{
    // Age first, then count: a quiet conversation is trimmed by age, a busy one by count.
    const QDateTime cutoff = QDateTime::currentDateTime().addDays(-MAX_AGE_DAYS);
    for (int i = messages.size() - 1; i >= 0; --i)
        if (messages.at(i).timestamp.isValid() && messages.at(i).timestamp < cutoff) messages.removeAt(i);
    while (messages.size() > MAX_PER_CHAT) messages.removeFirst();
}

void MessageStore::append(const QString &bareJid, const XmppMessage &message)
{
    QList<XmppMessage> all = load(bareJid);
    all.append(message);
    save(bareJid, all);
}

XmppMessage MessageStore::last(const QString &bareJid) const
{
    const QList<XmppMessage> all = load(bareJid);
    return all.isEmpty() ? XmppMessage() : all.last();
}

void MessageStore::clear(const QString &bareJid)
{
    QFile::remove(pathFor(bareJid));
}

void MessageStore::clearAll()
{
    QDir dir(m_dir);
    const QStringList files = dir.entryList(QStringList() << QLatin1String("*.dat"), QDir::Files);
    for (int i = 0; i < files.size(); ++i) dir.remove(files.at(i));
}
