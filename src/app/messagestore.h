// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// Message history on the phone: one file per conversation, the newest 500 messages and
// nothing older than six months (the same limits as JabberWP).
#ifndef SJ_MESSAGESTORE_H
#define SJ_MESSAGESTORE_H

#include "../xmpp/xmppclient.h"

#include <QList>
#include <QString>

class MessageStore
{
public:
    explicit MessageStore(const QString &dir);

    QList<XmppMessage> load(const QString &bareJid) const;
    void append(const QString &bareJid, const XmppMessage &message);
    void clear(const QString &bareJid);
    void clearAll();
    /// The last message of a conversation for the contact list preview (empty when none).
    XmppMessage last(const QString &bareJid) const;

private:
    QString pathFor(const QString &bareJid) const;
    void save(const QString &bareJid, QList<XmppMessage> messages) const;
    static void trim(QList<XmppMessage> &messages);

    QString m_dir;
};

#endif
