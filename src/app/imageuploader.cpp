// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "imageuploader.h"
#include "networkmanager.h"
#include "../omemo/omemomanager.h"

#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

ImageUploader::ImageUploader(XmppClient *client, NetworkManager *net, const QString &service,
                             const QByteArray &bytes, const QString &fileName, const QString &contentType, bool encrypt, QObject *parent)
    : QObject(parent), m_client(client), m_net(net), m_service(service), m_bytes(bytes), m_fileName(fileName),
      m_contentType(contentType), m_encrypt(encrypt)
{
}

void ImageUploader::fail(const QString &why)
{
    emit finished(false, QString(), why);
    deleteLater();
}

void ImageUploader::start()
{
    if (!m_client->isConnected()) { fail(tr("not connected")); return; }
    if (m_encrypt) {
        m_bytes = OmemoManager::encryptMedia(m_bytes, &m_key, &m_iv);
        m_contentType = QLatin1String("application/octet-stream");
        if (m_bytes.isEmpty()) { fail(tr("encryption failed")); return; }
    }
    if (!m_service.isEmpty()) { requestSlot(); return; }
    IqCall *call = m_client->request(m_client->boundJid().domain, QLatin1String("get"),
                                     XmlElement(QLatin1String(Xmpp::DISCO_ITEMS_NS), QLatin1String("query")));
    connect(call, SIGNAL(finished(IqCall*)), this, SLOT(onItems(IqCall*)));
}

void ImageUploader::onItems(IqCall *call)
{
    if (!call->isResult()) { fail(tr("the server did not list its services")); return; }
    const XmlElement query = call->reply().child(QLatin1String(Xmpp::DISCO_ITEMS_NS), QLatin1String("query"));
    const QList<XmlElement> items = query.childrenNamed(QLatin1String(Xmpp::DISCO_ITEMS_NS), QLatin1String("item"));
    for (int i = 0; i < items.size(); ++i) {
        const QString jid = items.at(i).attribute(QLatin1String("jid"));
        if (!jid.isEmpty()) m_candidates.append(jid);
    }
    // Some servers advertise upload on the domain itself rather than a component.
    m_candidates.append(m_client->boundJid().domain);
    discoverNext();
}

void ImageUploader::discoverNext()
{
    if (m_candidates.isEmpty()) { fail(tr("this server does not offer file upload (XEP-0363)")); return; }
    const QString jid = m_candidates.takeFirst();
    IqCall *call = m_client->request(jid, QLatin1String("get"), XmlElement(QLatin1String(Xmpp::DISCO_INFO_NS), QLatin1String("query")));
    call->setProperty("jid", jid);
    connect(call, SIGNAL(finished(IqCall*)), this, SLOT(onInfo(IqCall*)));
}

void ImageUploader::onInfo(IqCall *call)
{
    if (call->isResult()) {
        const XmlElement query = call->reply().child(QLatin1String(Xmpp::DISCO_INFO_NS), QLatin1String("query"));
        const QList<XmlElement> features = query.childrenNamed(QLatin1String(Xmpp::DISCO_INFO_NS), QLatin1String("feature"));
        for (int i = 0; i < features.size(); ++i) {
            const QString var = features.at(i).attribute(QLatin1String("var"));
            if (var == QLatin1String(Xmpp::HTTP_UPLOAD_NS) || var == QLatin1String(Xmpp::HTTP_UPLOAD_LEGACY_NS)) {
                m_service = call->property("jid").toString();
                requestSlot();
                return;
            }
        }
    }
    discoverNext();
}

void ImageUploader::requestSlot()
{
    XmlElement req(QLatin1String(Xmpp::HTTP_UPLOAD_NS), QLatin1String("request"));
    req.setAttribute(QLatin1String("filename"), m_fileName);
    req.setAttribute(QLatin1String("size"), QString::number(m_bytes.size()));
    req.setAttribute(QLatin1String("content-type"), m_contentType);
    IqCall *call = m_client->request(m_service, QLatin1String("get"), req, 30000);
    connect(call, SIGNAL(finished(IqCall*)), this, SLOT(onSlot(IqCall*)));
}

void ImageUploader::onSlot(IqCall *call)
{
    if (!call->isResult()) { fail(tr("the server refused the upload: %1").arg(call->errorText())); return; }
    UploadSlot slot;
    XmlElement s = call->reply().child(QLatin1String(Xmpp::HTTP_UPLOAD_NS), QLatin1String("slot"));
    if (!s.isNull()) {
        const XmlElement put = s.child(QLatin1String(Xmpp::HTTP_UPLOAD_NS), QLatin1String("put"));
        slot.putUrl = put.attribute(QLatin1String("url"));
        slot.getUrl = s.child(QLatin1String(Xmpp::HTTP_UPLOAD_NS), QLatin1String("get")).attribute(QLatin1String("url"));
        const QList<XmlElement> headers = put.childrenNamed(QLatin1String(Xmpp::HTTP_UPLOAD_NS), QLatin1String("header"));
        for (int i = 0; i < headers.size(); ++i) {
            const QString name = headers.at(i).attribute(QLatin1String("name"));
            if (!name.isEmpty()) slot.headers.insert(name, headers.at(i).text());
        }
    } else {
        // Legacy namespace: urls as element text.
        s = call->reply().child(QLatin1String(Xmpp::HTTP_UPLOAD_LEGACY_NS), QLatin1String("slot"));
        slot.putUrl = s.child(QLatin1String(Xmpp::HTTP_UPLOAD_LEGACY_NS), QLatin1String("put")).text();
        slot.getUrl = s.child(QLatin1String(Xmpp::HTTP_UPLOAD_LEGACY_NS), QLatin1String("get")).text();
    }
    if (!slot.isUsable()) { fail(tr("the server returned an unusable upload slot")); return; }
    m_getUrl = slot.getUrl;

    QNetworkRequest req;
    req.setUrl(QUrl::fromEncoded(slot.putUrl.toUtf8()));
    req.setHeader(QNetworkRequest::ContentTypeHeader, m_contentType);
    req.setHeader(QNetworkRequest::ContentLengthHeader, m_bytes.size());
    for (QMap<QString, QString>::const_iterator it = slot.headers.constBegin(); it != slot.headers.constEnd(); ++it) {
        // XEP-0363 allows only these to be forwarded.
        const QString n = it.key().toLower();
        if (n == QLatin1String("authorization") || n == QLatin1String("cookie") || n == QLatin1String("expires"))
            req.setRawHeader(it.key().toLatin1(), it.value().toUtf8());
    }
    QNetworkReply *reply = m_net->put(req, m_bytes);
    connect(reply, SIGNAL(finished()), this, SLOT(onPutFinished()));
}

void ImageUploader::onPutFinished()
{
    QNetworkReply *reply = qobject_cast<QNetworkReply *>(sender());
    if (!reply) return;
    reply->deleteLater();
    const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    if (reply->error() != QNetworkReply::NoError || status < 200 || status >= 300) {
        QString why = reply->errorString();
        const QString ssl = reply->property("sjSslErrors").toString();
        if (!ssl.isEmpty()) why += QLatin1String(" (") + ssl + QLatin1Char(')');
        fail(tr("upload failed: %1").arg(why));
        return;
    }
    const QString url = m_encrypt ? OmemoManager::buildAesGcmUrl(m_getUrl, m_iv, m_key) : m_getUrl;
    emit finished(true, url, QString());
    deleteLater();
}
