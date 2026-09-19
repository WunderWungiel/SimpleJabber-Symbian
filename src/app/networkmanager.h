// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// The QNetworkAccessManager for HTTP uploads (XEP-0363) and image downloads: the bundled
// root store on every https request, the bearer configuration on Symbian, and the same
// per-host certificate pins the XMPP stream honours.
#ifndef SJ_NETWORKMANAGER_H
#define SJ_NETWORKMANAGER_H

#include <QNetworkAccessManager>
#include <QNetworkConfiguration>
#include <QSslConfiguration>

class NetworkManager : public QNetworkAccessManager
{
    Q_OBJECT
public:
    explicit NetworkManager(QObject *parent = 0);

    static void setDefaultConfiguration(const QNetworkConfiguration &cfg);
    static bool sslSupported();

protected:
    QNetworkReply *createRequest(Operation op, const QNetworkRequest &request, QIODevice *outgoingData);

private slots:
    void onSslErrors(QNetworkReply *reply, const QList<QSslError> &errors);

private:
    QSslConfiguration m_ssl;
    static QNetworkConfiguration s_config;
    static bool s_hasConfig;
};

#endif
