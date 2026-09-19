// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// Sends a picture: finds the server's XEP-0363 upload component (disco#items, then
// disco#info on each item until one advertises http upload), asks it for a slot, PUTs the
// bytes (AES-GCM encrypted when the chat is OMEMO), and reports the URL to put in the
// message. One object per upload; it deletes itself after finished().
#ifndef SJ_IMAGEUPLOADER_H
#define SJ_IMAGEUPLOADER_H

#include "../xmpp/xmppclient.h"

#include <QByteArray>
#include <QObject>
#include <QStringList>

class NetworkManager;
class QNetworkReply;

class ImageUploader : public QObject
{
    Q_OBJECT
public:
    /// service: the upload component jid when already known (empty = discover).
    ImageUploader(XmppClient *client, NetworkManager *net, const QString &service,
                  const QByteArray &bytes, const QString &fileName, const QString &contentType, bool encrypt, QObject *parent = 0);
    void start();

    /// The upload component found, for the caller to cache.
    QString service() const { return m_service; }

signals:
    /// url is the https GET url, or the aesgcm:// url when encrypted.
    void finished(bool ok, const QString &url, const QString &error);

private slots:
    void onItems(IqCall *call);
    void onInfo(IqCall *call);
    void onSlot(IqCall *call);
    void onPutFinished();

private:
    void discoverNext();
    void requestSlot();
    void fail(const QString &why);

    XmppClient *m_client;
    NetworkManager *m_net;
    QString m_service;
    QByteArray m_bytes;
    QString m_fileName;
    QString m_contentType;
    bool m_encrypt;
    QByteArray m_key, m_iv;
    QStringList m_candidates;
    QString m_getUrl;
};

#endif
