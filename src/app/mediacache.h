// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// Downloads pictures once into the cache folder - decrypting aesgcm:// ones - and hands
// the chat a local file path. Everything runs on the main thread through the network
// manager, so no image provider thread is involved.
#ifndef SJ_MEDIACACHE_H
#define SJ_MEDIACACHE_H

#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>

class NetworkManager;
class QNetworkReply;

class MediaCache : public QObject
{
    Q_OBJECT
public:
    MediaCache(NetworkManager *net, const QString &cacheDir, QObject *parent = 0);

    /// The local path when already cached, otherwise empty.
    QString cachedPath(const QString &source) const;
    /// Starts a download unless one is running; ready() or failed() follows.
    void fetch(const QString &source);
    /// Stores already-decrypted bytes for a source (a picture we just sent).
    QString seed(const QString &source, const QByteArray &plain);
    void clear();

signals:
    void ready(const QString &source, const QString &path);
    void failed(const QString &source, const QString &error);

private slots:
    void onFinished();

private:
    QString pathFor(const QString &source) const;

    NetworkManager *m_net;
    QString m_dir;
    QHash<QNetworkReply *, QString> m_inFlight;
    QSet<QString> m_pending;
};

#endif
