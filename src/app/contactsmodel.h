// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// The contact list for QML: one row per conversation (roster contacts plus anyone who
// wrote to us), available contacts first, then alphabetical.
#ifndef SJ_CONTACTSMODEL_H
#define SJ_CONTACTSMODEL_H

#include "../xmpp/xmppclient.h"

#include <QAbstractListModel>
#include <QHash>
#include <QList>
#include <QSet>

struct Chat
{
    QString jid;           // bare, lowercase
    QString name;          // roster name (may be empty)
    QString subscription;
    PresenceShow presence;
    QString status;
    QString lastMessage;
    int unread;
    bool omemo;
    bool inRoster;
    Chat() : presence(PresenceOffline), unread(0), omemo(false), inRoster(false) {}
    QString displayName() const;
};

class ContactsModel : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(int count READ rowCount NOTIFY countChanged)
    Q_PROPERTY(int totalUnread READ totalUnread NOTIFY countChanged)
public:
    enum Roles {
        JidRole = Qt::UserRole + 1, NameRole, HasNameRole, PresenceRole, PresenceTextRole, StatusRole,
        LastMessageRole, UnreadRole, OmemoRole, InRosterRole
    };

    explicit ContactsModel(QObject *parent = 0);

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role) const;
    int totalUnread() const;

    Q_INVOKABLE QVariantMap get(int row) const;
    Q_INVOKABLE int indexOf(const QString &jid) const;

    bool contains(const QString &jid) const { return m_rows.contains(jid.toLower()); }
    Chat chat(const QString &jid) const { return m_rows.value(jid.toLower()); }
    /// Adds a row when missing; returns the (possibly new) chat.
    Chat &ensure(const QString &jid);
    void update(const Chat &chat);
    void remove(const QString &jid);
    void clear();
    QList<QString> jids() const { return m_order; }

    static QString presenceText(PresenceShow p, const QString &status);

signals:
    void countChanged();

private:
    void resort();
    QHash<QString, Chat> m_rows;
    QList<QString> m_order;
};

#endif
