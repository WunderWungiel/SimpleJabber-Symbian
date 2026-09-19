// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// The open conversation for QML: its stored history plus what arrives live, with link and
// inline-image detection (plain https images and aesgcm:// encrypted ones).
#ifndef SJ_MESSAGESMODEL_H
#define SJ_MESSAGESMODEL_H

#include "../xmpp/xmppclient.h"

#include <QAbstractListModel>
#include <QHash>
#include <QList>

class MessagesModel : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(int count READ rowCount NOTIFY countChanged)
    Q_PROPERTY(QString jid READ jid NOTIFY jidChanged)
public:
    enum Roles {
        IdRole = Qt::UserRole + 1, BodyRole, OutgoingRole, EncryptedRole, TimeTextRole, DateTextRole, ShowDateRole,
        IsImageRole, ImageSourceRole, ImagePathRole, HasUrlRole, UrlRole, PendingRole, FailedRole
    };

    explicit MessagesModel(QObject *parent = 0);

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role) const;
    QString jid() const { return m_jid; }

    void open(const QString &jid, const QList<XmppMessage> &history);
    void close();
    void append(const XmppMessage &message, bool pending = false);
    void markSent(const QString &id, bool ok);
    /// A downloaded/decrypted image is ready at path for the given source url.
    void setImagePath(const QString &source, const QString &path);

    Q_INVOKABLE QVariantMap get(int row) const;

    /// The first http(s) link in a body, trimmed of trailing punctuation.
    static QString firstUrl(const QString &body);
    /// True when the whole body is one image link (plain or aesgcm).
    static bool isImageMessage(const QString &body);

signals:
    void countChanged();
    void jidChanged();

private:
    static bool sameDay(const QDateTime &a, const QDateTime &b);
    QString m_jid;
    QList<XmppMessage> m_rows;
    QList<bool> m_pending;
    QList<bool> m_failed;
    QHash<QString, QString> m_imagePaths;   // source url -> local file
};

#endif
