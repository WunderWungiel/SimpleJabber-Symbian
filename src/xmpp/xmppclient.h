// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// One XMPP client session (RFC 6120/6121): connect, STARTTLS, SASL PLAIN, bind, legacy
// session, presence, roster; then messages, presence, subscriptions, roster edits, IQ
// requests with matched replies, and the XEP-0363 upload lookups. Free of any UI
// dependency; everything reaches the app through signals on the main thread.
#ifndef SJ_XMPPCLIENT_H
#define SJ_XMPPCLIENT_H

#include "xmlelement.h"
#include "xmppstream.h"

#include <QDateTime>
#include <QHash>
#include <QList>
#include <QMap>
#include <QObject>
#include <QString>

namespace Xmpp {
    const char *const CLIENT_NS = "jabber:client";
    const char *const STREAM_NS = "http://etherx.jabber.org/streams";
    const char *const TLS_NS = "urn:ietf:params:xml:ns:xmpp-tls";
    const char *const SASL_NS = "urn:ietf:params:xml:ns:xmpp-sasl";
    const char *const BIND_NS = "urn:ietf:params:xml:ns:xmpp-bind";
    const char *const SESSION_NS = "urn:ietf:params:xml:ns:xmpp-session";
    const char *const ROSTER_NS = "jabber:iq:roster";
    const char *const DISCO_ITEMS_NS = "http://jabber.org/protocol/disco#items";
    const char *const DISCO_INFO_NS = "http://jabber.org/protocol/disco#info";
    const char *const HTTP_UPLOAD_NS = "urn:xmpp:http:upload:0";
    const char *const HTTP_UPLOAD_LEGACY_NS = "urn:xmpp:http:upload";
    const char *const OOB_NS = "jabber:x:oob";
    const char *const STANZA_ERROR_NS = "urn:ietf:params:xml:ns:xmpp-stanzas";
    const int DEFAULT_PORT = 5222;
}

/// A bare or full JID split into parts.
struct Jid
{
    QString local, domain, resource;
    static Jid parse(const QString &value);
    static QString bareOf(const QString &value);
    QString bare() const { return local.isEmpty() ? domain : local + QLatin1Char('@') + domain; }
    QString full() const { return resource.isEmpty() ? bare() : bare() + QLatin1Char('/') + resource; }
    bool isValid() const { return !domain.isEmpty(); }
};

struct XmppAccount
{
    QString jid;
    QString password;
    QString host;        // optional override of the domain
    quint16 port;
    QString resource;
    bool requireTls;
    XmppAccount() : port(Xmpp::DEFAULT_PORT), resource(QLatin1String("SimpleJabber")), requireTls(true) {}
    QString effectiveHost() const { return host.isEmpty() ? Jid::parse(jid).domain : host; }
    bool isUsable() const;
};

enum PresenceShow { PresenceChat, PresenceOnline, PresenceAway, PresenceExtendedAway, PresenceDnd, PresenceOffline };

struct RosterItem
{
    QString jid;           // bare
    QString name;
    QString subscription;
    PresenceShow presence;
    QString status;
    RosterItem() : presence(PresenceOffline) {}
};

struct XmppMessage
{
    QString contactJid;    // bare
    QString body;
    bool outgoing;
    bool encrypted;        // OMEMO
    QDateTime timestamp;   // local time
    QString id;
    XmppMessage() : outgoing(false), encrypted(false), timestamp(QDateTime::currentDateTime()) {}
    XmppMessage(const QString &jid, const QString &b, bool out) : contactJid(jid), body(b), outgoing(out), encrypted(false), timestamp(QDateTime::currentDateTime()) {}
};

struct UploadSlot
{
    QString putUrl, getUrl;
    QMap<QString, QString> headers;
    bool isUsable() const { return !putUrl.isEmpty() && !getUrl.isEmpty(); }
};

class XmppClient;

/// One IQ request; finished() carries the reply (or a null element on timeout).
class IqCall : public QObject
{
    Q_OBJECT
public:
    QString id() const { return m_id; }
    const XmlElement &reply() const { return m_reply; }
    bool timedOut() const { return m_reply.isNull(); }
    bool isError() const { return !m_reply.isNull() && m_reply.attribute(QLatin1String("type")) == QLatin1String("error"); }
    bool isResult() const { return !m_reply.isNull() && m_reply.attribute(QLatin1String("type")) == QLatin1String("result"); }
    /// A short description of a stanza error, for messages.
    QString errorText() const;
signals:
    void finished(IqCall *call);
private slots:
    void onTimeout();
private:
    friend class XmppClient;
    IqCall(const QString &id, int timeoutMs, QObject *parent);
    void settle(const XmlElement &reply);
    QString m_id;
    XmlElement m_reply;
};

/// Gets first look at incoming <message> stanzas (the OMEMO layer). Return true when the
/// stanza was fully handled and the plaintext path must be skipped.
class MessageHook
{
public:
    virtual ~MessageHook() {}
    virtual bool handleIncomingMessage(const XmlElement &message) = 0;
};

class XmppClient : public QObject
{
    Q_OBJECT
public:
    enum State { Disconnected, Connecting, Securing, Authenticating, Binding, Connected, Failed };

    explicit XmppClient(QObject *parent = 0);

    State state() const { return m_state; }
    bool isConnected() const { return m_state == Connected; }
    Jid boundJid() const { return m_boundJid; }
    const XmppAccount &account() const { return m_account; }
    XmppStream *stream() const { return m_stream; }

    void setMessageHook(MessageHook *hook) { m_hook = hook; }

    void connectToServer(const XmppAccount &account);
    void disconnectFromServer();

    /// Sends a chat message; returns the stanza id (empty when not connected).
    QString sendMessage(const QString &toBare, const QString &body);
    /// Sends a shared-file message: the url as body plus XEP-0066 oob.
    QString sendFileUrl(const QString &toBare, const QString &url);
    void sendStanza(const XmlElement &stanza);
    void sendPresence(PresenceShow show, const QString &status);
    void setContactName(const QString &bareJid, const QString &name);
    void addContact(const QString &bareJid, const QString &name);
    void answerSubscription(const QString &bareJid, bool accepted, bool subscribeBack);
    void requestSubscription(const QString &bareJid);
    void removeContact(const QString &bareJid);

    /// Sends an IQ and returns the call whose finished() carries the matching reply.
    IqCall *request(const QString &to, const QString &type, const XmlElement &payload, int timeoutMs = 15000);

    /// Delivers a message the OMEMO layer decrypted along the normal path.
    void deliverMessage(const XmppMessage &message);

    /// A stanza id unique across sessions (random prefix + counter).
    QString nextId();

    static XmlElement iq(const QString &type, const QString &id, const XmlElement &payload);
    static QString showValue(PresenceShow show);
    static PresenceShow parseShow(const QString &show);
    static QString describeStanzaError(const XmlElement &stanza);

signals:
    void stateChanged(int state);
    void connectedToServer();
    /// The session ended (after connectToServer succeeded or failed); reason is readable.
    void closed(const QString &reason);
    void messageReceived(const XmppMessage &message);
    void rosterReceived(const QList<RosterItem> &items);
    void presenceChanged(const RosterItem &item);
    void subscriptionRequested(const QString &bareJid);
    void certificateRejected(const QString &host, const QString &fingerprint, const QString &subject, const QString &errors);

private slots:
    void onStreamConnected();
    void onStreamEncrypted();
    void onStreamOpened();
    void onElement(const XmlElement &element);
    void onStreamClosed();
    void onStreamDisconnected(const QString &reason);
    void onHandshakeTimeout();

private:
    enum Step { StepNone, StepFeatures, StepTlsProceed, StepFeaturesAfterTls, StepSasl, StepFeaturesAfterSasl, StepBind, StepSession };

    void setState(State s);
    void fail(const QString &reason);
    void handleFeatures(const XmlElement &features);
    void startAuth();
    void startBind();
    void startSession();
    void finishHandshake();
    void handleMessage(const XmlElement &stanza);
    void handlePresence(const XmlElement &stanza);
    void handleIq(const XmlElement &stanza);
    void armHandshakeTimer();

    XmppStream *m_stream;
    XmppAccount m_account;
    State m_state;
    Step m_step;
    Jid m_boundJid;
    QString m_domain;
    QString m_idPrefix;
    int m_idCounter;
    QString m_pendingBindId, m_pendingSessionId;
    bool m_sessionOffered;
    QHash<QString, IqCall *> m_pendingIq;
    MessageHook *m_hook;
    QTimer *m_handshakeTimer;
};

#endif
