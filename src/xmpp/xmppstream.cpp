// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "xmppstream.h"

#include "../crypto/sha256.h"

#include <QFile>
#include <QHash>
#include <QSslConfiguration>
#include <QSslSocket>
#include <QStringList>
#include <QTimer>
#include <QXmlStreamAttributes>
#include <QDebug>

namespace {
const char *const STREAM_NS = "http://etherx.jabber.org/streams";
const int KEEPALIVE_MS = 60 * 1000;

QHash<QString, QString> &pins()
{
    static QHash<QString, QString> p;
    return p;
}

const QList<QSslCertificate> &rootCertificates()
{
    static QList<QSslCertificate> roots;
    static bool loaded = false;
    if (!loaded) {
        loaded = true;
        QFile f(QLatin1String(":/certs/roots.pem"));
        if (f.open(QIODevice::ReadOnly)) roots = QSslCertificate::fromData(f.readAll(), QSsl::Pem);
        if (roots.isEmpty()) qWarning("XmppStream: no root certificates bundled");
    }
    return roots;
}
}

XmppStream::XmppStream(QObject *parent)
    : QObject(parent), m_socket(new QSslSocket(this)), m_keepAlive(new QTimer(this)),
      m_depth(0), m_open(false), m_closing(false), m_failed(false)
{
    connect(m_socket, SIGNAL(connected()), this, SLOT(onConnected()));
    connect(m_socket, SIGNAL(encrypted()), this, SLOT(onEncrypted()));
    connect(m_socket, SIGNAL(readyRead()), this, SLOT(onReadyRead()));
    connect(m_socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(onSocketError()));
    connect(m_socket, SIGNAL(disconnected()), this, SLOT(onSocketDisconnected()));
    connect(m_socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(onSslErrors(QList<QSslError>)));

    m_keepAlive->setInterval(KEEPALIVE_MS);
    connect(m_keepAlive, SIGNAL(timeout()), this, SLOT(onKeepAlive()));
}

XmppStream::~XmppStream()
{
    m_socket->abort();
}

void XmppStream::setPinnedCertificate(const QString &host, const QString &sha256Hex)
{
    if (sha256Hex.isEmpty()) pins().remove(host.toLower());
    else pins().insert(host.toLower(), sha256Hex.toLower());
}

QString XmppStream::pinnedCertificate(const QString &host)
{
    return pins().value(host.toLower());
}

QString XmppStream::fingerprintOf(const QSslCertificate &cert)
{
    // Qt 4's QCryptographicHash stops at SHA-1; the app's own SHA-256 is used instead.
    const QByteArray der = cert.toDer();
    if (der.isEmpty()) return QString();
    unsigned char digest[32];
    sha256(reinterpret_cast<const unsigned char *>(der.constData()), der.size(), digest);
    return QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(digest), 32).toHex());
}

bool XmppStream::isEncrypted() const { return m_socket->isEncrypted(); }
bool XmppStream::isOpen() const { return m_open && m_socket->state() == QAbstractSocket::ConnectedState; }

void XmppStream::connectToHost(const QString &host, quint16 port, const QString &tlsHostname)
{
    m_host = host;
    m_tlsHostname = tlsHostname;
    m_failed = false;
    m_closing = false;
    m_open = false;
    m_streamId.clear();
    m_pendingCertError.clear();
    resetReader();

    QSslConfiguration cfg = m_socket->sslConfiguration();
    cfg.setCaCertificates(rootCertificates());
    cfg.setPeerVerifyMode(QSslSocket::VerifyPeer);
#if QT_VERSION >= 0x040800
    cfg.setProtocol(QSsl::SecureProtocols);
#else
    cfg.setProtocol(QSsl::AnyProtocol);   // SSLv23 method: negotiates up to TLS 1.2
#endif
    m_socket->setSslConfiguration(cfg);
#if QT_VERSION >= 0x040800
    m_socket->setPeerVerifyName(tlsHostname);
#endif
    // Qt 4.7 verifies the certificate against the name given to connectToHost; with a host
    // override that differs from the JID domain a mismatch ends in the "trust it?" prompt.
    m_socket->connectToHost(host, port);
}

void XmppStream::startTls()
{
#if QT_VERSION >= 0x040800
    m_socket->setPeerVerifyName(m_tlsHostname);
#endif
    m_socket->startClientEncryption();
}

void XmppStream::resetReader()
{
    m_reader.clear();
    m_stack.clear();
    m_depth = 0;
}

void XmppStream::openStream(const QString &domain)
{
    resetReader();
    m_open = false;
    // Deliberately unclosed, so it cannot come from an XmlElement.
    sendRaw(QLatin1String("<?xml version='1.0'?><stream:stream to='") + XmlElement::escape(domain) +
            QLatin1String("' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"));
}

void XmppStream::send(const XmlElement &element)
{
    sendRaw(element.toXml(QLatin1String("jabber:client")));
}

void XmppStream::sendRaw(const QString &xml)
{
    if (m_socket->state() != QAbstractSocket::ConnectedState) return;
    m_socket->write(xml.toUtf8());
}

void XmppStream::close()
{
    if (m_socket->state() != QAbstractSocket::ConnectedState) { abort(); return; }
    m_closing = true;
    m_keepAlive->stop();
    if (m_open) sendRaw(QLatin1String("</stream:stream>"));
    m_socket->flush();
    m_socket->disconnectFromHost();
    // Don't wait for the server's own </stream:stream>; a 2 s grace then abort.
    QTimer::singleShot(2000, this, SLOT(onCloseTimeout()));
}

void XmppStream::onCloseTimeout()
{
    if (m_socket->state() != QAbstractSocket::UnconnectedState) m_socket->abort();
}

void XmppStream::abort()
{
    m_closing = true;
    m_keepAlive->stop();
    m_socket->abort();
    m_open = false;
}

void XmppStream::onConnected()
{
    m_keepAlive->start();
    emit connected();
}

void XmppStream::onEncrypted()
{
    emit encrypted();
}

void XmppStream::onKeepAlive()
{
    // Whitespace between stanzas is legal XMPP; it keeps NAT mappings and the socket alive.
    if (m_open && m_socket->state() == QAbstractSocket::ConnectedState) m_socket->write(" ", 1);
}

void XmppStream::onSslErrors(const QList<QSslError> &errors)
{
    const QSslCertificate leaf = m_socket->peerCertificate();
    const QString fp = fingerprintOf(leaf);
    if (!fp.isEmpty() && pinnedCertificate(m_tlsHostname) == fp) {
        m_socket->ignoreSslErrors();
        return;
    }
    QStringList texts;
    for (int i = 0; i < errors.size(); ++i)
        if (errors.at(i).error() != QSslError::NoError) texts.append(errors.at(i).errorString());
    if (texts.isEmpty()) texts.append(tr("the certificate could not be verified"));
    m_pendingCertError = texts.join(QLatin1String("; "));
    emit certificateRejected(m_tlsHostname, fp, leaf.subjectInfo(QSslCertificate::CommonName), m_pendingCertError);
    // Not ignored: the handshake fails and onSocketError reports it.
}

void XmppStream::onSocketError()
{
    if (m_closing) return;
    QString why = m_socket->errorString();
    if (!m_pendingCertError.isEmpty()) why = tr("certificate not trusted: ") + m_pendingCertError;
    fail(why);
}

void XmppStream::onSocketDisconnected()
{
    m_keepAlive->stop();
    m_open = false;
    if (m_failed) return;
    if (!m_closing) fail(tr("connection closed"));
}

void XmppStream::fail(const QString &reason)
{
    if (m_failed) return;
    m_failed = true;
    m_keepAlive->stop();
    m_open = false;
    if (m_socket->state() != QAbstractSocket::UnconnectedState) m_socket->abort();
    emit disconnected(reason);
}

void XmppStream::onReadyRead()
{
    const QByteArray data = m_socket->readAll();
    if (data.isEmpty()) return;
    m_reader.addData(data);
    parse();
}

void XmppStream::parse()
{
    // readNext() answers Invalid/PrematureEndOfDocumentError once the buffered bytes are
    // used up; addData() from the next readyRead resumes exactly there.
    for (;;) {
        const QXmlStreamReader::TokenType token = m_reader.readNext();
        switch (token) {
        case QXmlStreamReader::Invalid:
            if (m_reader.error() == QXmlStreamReader::PrematureEndOfDocumentError) return;   // need more bytes
            fail(tr("stream error: ") + m_reader.errorString());
            return;
        case QXmlStreamReader::StartElement: {
            if (m_depth == 0) {
                if (m_reader.namespaceUri() != QLatin1String(STREAM_NS) || m_reader.name() != QLatin1String("stream")) {
                    fail(tr("unexpected stream root"));
                    return;
                }
                m_streamId = m_reader.attributes().value(QLatin1String("id")).toString();
                m_depth = 1;
                m_open = true;
                emit streamOpened();
                break;
            }
            XmlElement el(m_reader.namespaceUri().toString(), m_reader.name().toString());
            const QXmlStreamAttributes attrs = m_reader.attributes();
            for (int i = 0; i < attrs.size(); ++i)
                el.setAttribute(attrs.at(i).qualifiedName().toString(), attrs.at(i).value().toString());
            m_stack.append(el);
            ++m_depth;
            break;
        }
        case QXmlStreamReader::Characters:
            if (!m_stack.isEmpty()) m_stack.last().appendText(m_reader.text().toString());
            break;
        case QXmlStreamReader::EndElement: {
            --m_depth;
            if (m_depth <= 0) {
                m_depth = 0;
                m_open = false;
                emit streamClosed();
                break;
            }
            if (m_stack.isEmpty()) break;
            const XmlElement done = m_stack.takeLast();
            if (m_stack.isEmpty()) emit elementReceived(done);
            else m_stack.last().addChild(done);
            break;
        }
        case QXmlStreamReader::EndDocument:
            m_open = false;
            emit streamClosed();
            return;
        default:
            break;
        }
        if (m_failed) return;
    }
}
