// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "contactsmodel.h"

#include <QCoreApplication>
#include <algorithm>

QString Chat::displayName() const
{
    if (!name.isEmpty()) return name;
    const Jid j = Jid::parse(jid);
    return j.local.isEmpty() ? jid : j.local;
}

ContactsModel::ContactsModel(QObject *parent)
    : QAbstractListModel(parent)
{
    QHash<int, QByteArray> roles;
    roles[JidRole] = "jid";
    roles[NameRole] = "name";
    roles[HasNameRole] = "hasName";
    roles[PresenceRole] = "presence";
    roles[PresenceTextRole] = "presenceText";
    roles[StatusRole] = "status";
    roles[LastMessageRole] = "lastMessage";
    roles[UnreadRole] = "unread";
    roles[OmemoRole] = "omemo";
    roles[InRosterRole] = "inRoster";
    setRoleNames(roles);
}

int ContactsModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_order.size();
}

int ContactsModel::totalUnread() const
{
    int n = 0;
    for (QHash<QString, Chat>::const_iterator it = m_rows.constBegin(); it != m_rows.constEnd(); ++it) n += it->unread;
    return n;
}

QString ContactsModel::presenceText(PresenceShow p, const QString &status)
{
    if (!status.isEmpty()) return status;
    switch (p) {
    case PresenceChat: return QCoreApplication::translate("ContactsModel", "free to chat");
    case PresenceOnline: return QCoreApplication::translate("ContactsModel", "online");
    case PresenceAway: return QCoreApplication::translate("ContactsModel", "away");
    case PresenceExtendedAway: return QCoreApplication::translate("ContactsModel", "away for a while");
    case PresenceDnd: return QCoreApplication::translate("ContactsModel", "do not disturb");
    default: return QCoreApplication::translate("ContactsModel", "offline");
    }
}

QVariant ContactsModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= m_order.size()) return QVariant();
    const Chat &c = m_rows[m_order.at(index.row())];
    switch (role) {
    case JidRole: return c.jid;
    case NameRole: return c.displayName();
    case HasNameRole: return !c.name.isEmpty();
    case PresenceRole: return int(c.presence);
    case PresenceTextRole: return presenceText(c.presence, c.status);
    case StatusRole: return c.status;
    case LastMessageRole: return c.lastMessage;
    case UnreadRole: return c.unread;
    case OmemoRole: return c.omemo;
    case InRosterRole: return c.inRoster;
    }
    return QVariant();
}

QVariantMap ContactsModel::get(int row) const
{
    QVariantMap m;
    if (row < 0 || row >= m_order.size()) return m;
    const QModelIndex idx = index(row);
    const QHash<int, QByteArray> names = roleNames();
    for (QHash<int, QByteArray>::const_iterator it = names.constBegin(); it != names.constEnd(); ++it)
        m.insert(QString::fromLatin1(it.value()), data(idx, it.key()));
    return m;
}

int ContactsModel::indexOf(const QString &jid) const
{
    return m_order.indexOf(jid.toLower());
}

Chat &ContactsModel::ensure(const QString &jidIn)
{
    const QString jid = jidIn.toLower();
    if (!m_rows.contains(jid)) {
        Chat c;
        c.jid = jid;
        m_rows.insert(jid, c);
        m_order.append(jid);
        resort();
    }
    return m_rows[jid];
}

void ContactsModel::update(const Chat &chat)
{
    const QString jid = chat.jid.toLower();
    const bool existed = m_rows.contains(jid);
    Chat c = chat;
    c.jid = jid;
    m_rows.insert(jid, c);
    if (!existed) m_order.append(jid);
    resort();
}

void ContactsModel::remove(const QString &jidIn)
{
    const QString jid = jidIn.toLower();
    if (!m_rows.contains(jid)) return;
    m_rows.remove(jid);
    m_order.removeAll(jid);
    resort();
}

void ContactsModel::clear()
{
    beginResetModel();
    m_rows.clear();
    m_order.clear();
    endResetModel();
    emit countChanged();
}

namespace {
struct Sorter
{
    const QHash<QString, Chat> *rows;
    static int rank(PresenceShow p)
    {
        switch (p) { case PresenceChat: return 0; case PresenceOnline: return 1; case PresenceAway: return 2;
                     case PresenceExtendedAway: return 3; case PresenceDnd: return 4; default: return 5; }
    }
    bool operator()(const QString &a, const QString &b) const
    {
        const Chat &ca = (*rows)[a];
        const Chat &cb = (*rows)[b];
        if (ca.unread != cb.unread) return ca.unread > cb.unread;
        const int ra = rank(ca.presence), rb = rank(cb.presence);
        if (ra != rb) return ra < rb;
        return QString::compare(ca.displayName(), cb.displayName(), Qt::CaseInsensitive) < 0;
    }
};
}

void ContactsModel::resort()
{
    // A reset is the simplest correct update for a QtQuick 1 ListView; the list is short.
    beginResetModel();
    Sorter s;
    s.rows = &m_rows;
    std::stable_sort(m_order.begin(), m_order.end(), s);
    endResetModel();
    emit countChanged();
}
