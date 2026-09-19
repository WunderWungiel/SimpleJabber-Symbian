// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "mediacache.h"
#include "networkmanager.h"
#include "../omemo/omemomanager.h"
#include "../crypto/sha256.h"

#include <QDir>
#include <QFile>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QUrl>

MediaCache::MediaCache(NetworkManager *net, const QString &cacheDir, QObject *parent)
    : QObject(parent), m_net(net), m_dir(cacheDir)
{
    QDir().mkpath(m_dir);
}

QString MediaCache::pathFor(const QString &source) const
{
    const QByteArray utf = source.toUtf8();
    unsigned char digest[32];
    sha256(reinterpret_cast<const unsigned char *>(utf.constData()), utf.size(), digest);
    QString base = source;
    const int hash = base.indexOf(QLatin1Char('#'));
    if (hash >= 0) base = base.left(hash);
    const int q = base.indexOf(QLatin1Char('?'));
    if (q >= 0) base = base.left(q);
    QString ext = QLatin1String("img");
    const int dot = base.lastIndexOf(QLatin1Char('.'));
    if (dot >= 0 && base.size() - dot <= 5) ext = base.mid(dot + 1).toLower();
    return m_dir + QLatin1Char('/') + QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(digest), 16).toHex()) + QLatin1Char('.') + ext;
}

QString MediaCache::cachedPath(const QString &source) const
{
    const QString p = pathFor(source);
    return QFile::exists(p) ? p : QString();
}

QString MediaCache::seed(const QString &source, const QByteArray &plain)
{
    const QString p = pathFor(source);
    QFile f(p);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) f.write(plain);
    return p;
}

void MediaCache::clear()
{
    QDir dir(m_dir);
    const QStringList files = dir.entryList(QDir::Files);
    for (int i = 0; i < files.size(); ++i) dir.remove(files.at(i));
}

void MediaCache::fetch(const QString &source)
{
    if (m_pending.contains(source)) return;
    const QString cached = cachedPath(source);
    if (!cached.isEmpty()) { emit ready(source, cached); return; }

    QString url = source;
    if (OmemoManager::isAesGcmUrl(source)) {
        QByteArray key, iv;
        if (!OmemoManager::parseAesGcmUrl(source, &url, &key, &iv)) { emit failed(source, tr("bad aesgcm link")); return; }
    }
    QNetworkRequest req;
    req.setUrl(QUrl::fromEncoded(url.toUtf8()));
    QNetworkReply *reply = m_net->get(req);
    m_inFlight.insert(reply, source);
    m_pending.insert(source);
    connect(reply, SIGNAL(finished()), this, SLOT(onFinished()));
}

void MediaCache::onFinished()
{
    QNetworkReply *reply = qobject_cast<QNetworkReply *>(sender());
    if (!reply) return;
    reply->deleteLater();
    const QString source = m_inFlight.take(reply);
    m_pending.remove(source);
    if (source.isEmpty()) return;

    if (reply->error() != QNetworkReply::NoError) {
        QString why = reply->errorString();
        const QString ssl = reply->property("sjSslErrors").toString();
        if (!ssl.isEmpty()) why += QLatin1String(" (") + ssl + QLatin1Char(')');
        emit failed(source, why);
        return;
    }
    // A redirect (upload hosts often bounce to a CDN): follow it once.
    const QVariant redirect = reply->attribute(QNetworkRequest::RedirectionTargetAttribute);
    if (redirect.isValid()) {
        QNetworkRequest req;
        req.setUrl(reply->url().resolved(redirect.toUrl()));
        QNetworkReply *again = m_net->get(req);
        m_inFlight.insert(again, source);
        m_pending.insert(source);
        connect(again, SIGNAL(finished()), this, SLOT(onFinished()));
        return;
    }

    QByteArray bytes = reply->readAll();
    if (OmemoManager::isAesGcmUrl(source)) {
        QString url;
        QByteArray key, iv, plain;
        if (!OmemoManager::parseAesGcmUrl(source, &url, &key, &iv) || !OmemoManager::decryptMedia(bytes, key, iv, &plain)) {
            emit failed(source, tr("could not decrypt the picture"));
            return;
        }
        bytes = plain;
    }
    const QString path = pathFor(source);
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate) || f.write(bytes) != bytes.size()) {
        emit failed(source, tr("could not save the picture"));
        return;
    }
    f.close();
    emit ready(source, path);
}
