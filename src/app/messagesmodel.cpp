// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "messagesmodel.h"
#include "../omemo/omemomanager.h"

#include <QDate>
#include <QStringList>

MessagesModel::MessagesModel(QObject *parent)
    : QAbstractListModel(parent)
{
    QHash<int, QByteArray> roles;
    roles[IdRole] = "messageId";
    roles[BodyRole] = "body";
    roles[OutgoingRole] = "outgoing";
    roles[EncryptedRole] = "encrypted";
    roles[TimeTextRole] = "timeText";
    roles[DateTextRole] = "dateText";
    roles[ShowDateRole] = "showDate";
    roles[IsImageRole] = "isImage";
    roles[ImageSourceRole] = "imageSource";
    roles[ImagePathRole] = "imagePath";
    roles[HasUrlRole] = "hasUrl";
    roles[UrlRole] = "url";
    roles[PendingRole] = "pending";
    roles[FailedRole] = "failed";
    setRoleNames(roles);
}

int MessagesModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : m_rows.size();
}

QString MessagesModel::firstUrl(const QString &body)
{
    const QStringList tokens = body.split(QRegExp(QLatin1String("\\s+")), QString::SkipEmptyParts);
    for (int i = 0; i < tokens.size(); ++i) {
        QString t = tokens.at(i);
        if (t.startsWith(QLatin1String("http://"), Qt::CaseInsensitive) || t.startsWith(QLatin1String("https://"), Qt::CaseInsensitive)) {
            while (!t.isEmpty() && QString::fromLatin1(".,)]>\"'").contains(t.at(t.size() - 1))) t.chop(1);
            return t;
        }
    }
    return QString();
}

bool MessagesModel::isImageMessage(const QString &body)
{
    const QString t = body.trimmed();
    if (t.contains(QLatin1Char(' '))) return false;
    if (OmemoManager::isAesGcmImageUrl(t)) return true;
    if (!t.startsWith(QLatin1String("http://"), Qt::CaseInsensitive) && !t.startsWith(QLatin1String("https://"), Qt::CaseInsensitive)) return false;
    QString path = t;
    const int q = path.indexOf(QLatin1Char('?'));
    if (q >= 0) path = path.left(q);
    path = path.toLower();
    return path.endsWith(QLatin1String(".jpg")) || path.endsWith(QLatin1String(".jpeg")) || path.endsWith(QLatin1String(".png"))
        || path.endsWith(QLatin1String(".gif")) || path.endsWith(QLatin1String(".bmp"));
}

bool MessagesModel::sameDay(const QDateTime &a, const QDateTime &b)
{
    return a.isValid() && b.isValid() && a.date() == b.date();
}

QVariant MessagesModel::data(const QModelIndex &index, int role) const
{
    const int row = index.row();
    if (!index.isValid() || row >= m_rows.size()) return QVariant();
    const XmppMessage &m = m_rows.at(row);
    switch (role) {
    case IdRole: return m.id;
    case BodyRole: return m.body;
    case OutgoingRole: return m.outgoing;
    case EncryptedRole: return m.encrypted;
    case TimeTextRole: return m.timestamp.toString(QLatin1String("HH:mm"));
    case DateTextRole: {
        const QDate d = m.timestamp.date();
        if (d == QDate::currentDate()) return tr("Today");
        if (d == QDate::currentDate().addDays(-1)) return tr("Yesterday");
        return d.toString(d.year() == QDate::currentDate().year() ? QLatin1String("d MMMM") : QLatin1String("d MMMM yyyy"));
    }
    case ShowDateRole: return row == 0 || !sameDay(m.timestamp, m_rows.at(row - 1).timestamp);
    case IsImageRole: return isImageMessage(m.body);
    case ImageSourceRole: return isImageMessage(m.body) ? m.body.trimmed() : QString();
    case ImagePathRole: return m_imagePaths.value(m.body.trimmed());
    case HasUrlRole: return !firstUrl(m.body).isEmpty() && !OmemoManager::isAesGcmUrl(m.body);
    case UrlRole: return firstUrl(m.body);
    case PendingRole: return m_pending.at(row);
    case FailedRole: return m_failed.at(row);
    }
    return QVariant();
}

QVariantMap MessagesModel::get(int row) const
{
    QVariantMap out;
    if (row < 0 || row >= m_rows.size()) return out;
    const QModelIndex idx = index(row);
    const QHash<int, QByteArray> names = roleNames();
    for (QHash<int, QByteArray>::const_iterator it = names.constBegin(); it != names.constEnd(); ++it)
        out.insert(QString::fromLatin1(it.value()), data(idx, it.key()));
    return out;
}

void MessagesModel::open(const QString &jid, const QList<XmppMessage> &history)
{
    beginResetModel();
    m_jid = jid.toLower();
    m_rows = history;
    m_pending.clear();
    m_failed.clear();
    for (int i = 0; i < m_rows.size(); ++i) { m_pending.append(false); m_failed.append(false); }
    endResetModel();
    emit jidChanged();
    emit countChanged();
}

void MessagesModel::close()
{
    beginResetModel();
    m_jid.clear();
    m_rows.clear();
    m_pending.clear();
    m_failed.clear();
    endResetModel();
    emit jidChanged();
    emit countChanged();
}

void MessagesModel::append(const XmppMessage &message, bool pending)
{
    beginInsertRows(QModelIndex(), m_rows.size(), m_rows.size());
    m_rows.append(message);
    m_pending.append(pending);
    m_failed.append(false);
    endInsertRows();
    emit countChanged();
}

void MessagesModel::markSent(const QString &id, bool ok)
{
    for (int i = m_rows.size() - 1; i >= 0; --i) {
        if (m_rows.at(i).id != id) continue;
        m_pending[i] = false;
        m_failed[i] = !ok;
        const QModelIndex idx = index(i);
        emit dataChanged(idx, idx);
        return;
    }
}

void MessagesModel::setImagePath(const QString &source, const QString &path)
{
    m_imagePaths.insert(source, path);
    for (int i = 0; i < m_rows.size(); ++i) {
        if (m_rows.at(i).body.trimmed() == source) {
            const QModelIndex idx = index(i);
            emit dataChanged(idx, idx);
        }
    }
}
