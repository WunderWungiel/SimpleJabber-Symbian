// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// The byte layer of an XMPP session: one QSslSocket (plain until STARTTLS), and an
// incremental XML reader that turns the never-ending <stream:stream> document into
// XmlElement stanzas. The stream restarts after TLS and after SASL; each restart is a
// brand-new XML document, so the reader is reset then.
//
// TLS trust: the bundled root store (certs/roots.pem) plus per-host pins the user accepted
// ("trust this certificate"). An unverifiable certificate fails the connection and is
// reported through certificateRejected() so the UI can offer to pin it.
#ifndef SJ_XMPPSTREAM_H
#define SJ_XMPPSTREAM_H

#include "xmlelement.h"

#include <QList>
#include <QObject>
#include <QSslCertificate>
#include <QSslError>
#include <QString>
#include <QXmlStreamReader>

class QSslSocket;
class QTimer;

class XmppStream : public QObject
{
    Q_OBJECT
public:
    explicit XmppStream(QObject *parent = 0);
    ~XmppStream();

    void connectToHost(const QString &host, quint16 port, const QString &tlsHostname);
    /// Upgrades the plain connection (after <proceed/>); encrypted() or disconnected() follows.
    void startTls();
    /// Sends the opening stream header for `domain` and resets the reader.
    void openStream(const QString &domain);
    void send(const XmlElement &element);
    void sendRaw(const QString &xml);
    /// Sends </stream:stream> and closes.
    void close();
    void abort();

    bool isEncrypted() const;
    bool isOpen() const;
    /// The id attribute the server put on its stream header (empty before it arrives).
    QString streamId() const { return m_streamId; }

    /// Per-host certificate pins (SHA-256 of the DER, lowercase hex).
    static void setPinnedCertificate(const QString &host, const QString &sha256Hex);
    static QString pinnedCertificate(const QString &host);
    static QString fingerprintOf(const QSslCertificate &cert);

signals:
    void connected();
    void encrypted();
    /// The server's <stream:stream> header arrived (after each open).
    void streamOpened();
    void elementReceived(const XmlElement &element);
    /// The server closed its side of the stream.
    void streamClosed();
    void disconnected(const QString &reason);
    /// TLS verification failed: the offered leaf certificate, for the "trust it?" prompt.
    void certificateRejected(const QString &host, const QString &fingerprint, const QString &subject, const QString &errors);

private slots:
    void onConnected();
    void onEncrypted();
    void onReadyRead();
    void onSocketError();
    void onSocketDisconnected();
    void onSslErrors(const QList<QSslError> &errors);
    void onKeepAlive();
    void onCloseTimeout();

private:
    void parse();
    void resetReader();
    void fail(const QString &reason);

    QSslSocket *m_socket;
    QXmlStreamReader m_reader;
    QTimer *m_keepAlive;
    QList<XmlElement> m_stack;   // open elements below <stream:stream>
    QString m_host;
    QString m_tlsHostname;
    QString m_streamId;
    QString m_pendingCertError;
    int m_depth;
    bool m_open;
    bool m_closing;
    bool m_failed;
};

#endif
