// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "networkmanager.h"
#include "../xmpp/xmppstream.h"

#include <QFile>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslCertificate>
#include <QSslSocket>
#include <QStringList>
#include <QDebug>

QNetworkConfiguration NetworkManager::s_config;
bool NetworkManager::s_hasConfig = false;

NetworkManager::NetworkManager(QObject *parent)
    : QNetworkAccessManager(parent)
{
    m_ssl = QSslConfiguration::defaultConfiguration();
    QFile pem(QLatin1String(":/certs/roots.pem"));
    if (pem.open(QIODevice::ReadOnly)) {
        const QList<QSslCertificate> roots = QSslCertificate::fromData(pem.readAll(), QSsl::Pem);
        if (!roots.isEmpty()) m_ssl.setCaCertificates(roots);
    }
    m_ssl.setPeerVerifyMode(QSslSocket::VerifyPeer);
#if QT_VERSION >= 0x040800
    m_ssl.setProtocol(QSsl::SecureProtocols);
#else
    m_ssl.setProtocol(QSsl::AnyProtocol);
#endif
    if (s_hasConfig) setConfiguration(s_config);
    connect(this, SIGNAL(sslErrors(QNetworkReply*,QList<QSslError>)), this, SLOT(onSslErrors(QNetworkReply*,QList<QSslError>)));
}

void NetworkManager::setDefaultConfiguration(const QNetworkConfiguration &cfg)
{
    s_config = cfg;
    s_hasConfig = cfg.isValid();
}

bool NetworkManager::sslSupported()
{
    return QSslSocket::supportsSsl();
}

QNetworkReply *NetworkManager::createRequest(Operation op, const QNetworkRequest &request, QIODevice *outgoingData)
{
    QNetworkRequest r(request);
    if (!r.hasRawHeader("User-Agent")) r.setRawHeader("User-Agent", "SimpleJabber/1.0 (Symbian)");
    if (r.url().scheme() == QLatin1String("https")) r.setSslConfiguration(m_ssl);
    return QNetworkAccessManager::createRequest(op, r, outgoingData);
}

void NetworkManager::onSslErrors(QNetworkReply *reply, const QList<QSslError> &errors)
{
    // The upload/download host is usually the XMPP server itself; a certificate the user
    // pinned for it is honoured here too.
    const QSslCertificate leaf = reply->sslConfiguration().peerCertificate();
    const QString fp = XmppStream::fingerprintOf(leaf);
    if (!fp.isEmpty() && XmppStream::pinnedCertificate(reply->url().host()) == fp) {
        reply->ignoreSslErrors();
        return;
    }
    QStringList texts;
    for (int i = 0; i < errors.size(); ++i) texts.append(errors.at(i).errorString());
    reply->setProperty("sjSslErrors", texts.join(QLatin1String("; ")));
}
