// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "xmppclient.h"

#include <QTimer>
#include <QUuid>
#include <QDebug>

namespace {
const int HANDSHAKE_TIMEOUT_MS = 25000;
}

// -- Jid / account -------------------------------------------------------------------

Jid Jid::parse(const QString &value)
{
    Jid j;
    QString v = value.trimmed();
    if (v.isEmpty()) return j;
    const int slash = v.indexOf(QLatin1Char('/'));
    if (slash >= 0) { j.resource = v.mid(slash + 1); v = v.left(slash); }
    const int at = v.indexOf(QLatin1Char('@'));
    if (at >= 0) { j.local = v.left(at); j.domain = v.mid(at + 1); }
    else j.domain = v;
    j.local = j.local.toLower();
    j.domain = j.domain.toLower();
    return j;
}

QString Jid::bareOf(const QString &value)
{
    const Jid j = parse(value);
    return j.isValid() ? j.bare() : QString();
}

bool XmppAccount::isUsable() const
{
    const Jid j = Jid::parse(jid);
    return j.isValid() && !j.local.isEmpty() && !password.isEmpty() && !effectiveHost().isEmpty() && port > 0;
}

// -- IqCall --------------------------------------------------------------------------

IqCall::IqCall(const QString &id, int timeoutMs, QObject *parent)
    : QObject(parent), m_id(id)
{
    QTimer::singleShot(timeoutMs, this, SLOT(onTimeout()));
}

void IqCall::onTimeout()
{
    settle(XmlElement());
}

void IqCall::settle(const XmlElement &reply)
{
    m_reply = reply;
    emit finished(this);
    deleteLater();
}

QString IqCall::errorText() const
{
    if (m_reply.isNull()) return QObject::tr("no reply from the server");
    return XmppClient::describeStanzaError(m_reply);
}

// -- XmppClient ----------------------------------------------------------------------

XmppClient::XmppClient(QObject *parent)
    : QObject(parent), m_stream(new XmppStream(this)), m_state(Disconnected), m_step(StepNone),
      m_idCounter(0), m_sessionOffered(false), m_hook(0), m_handshakeTimer(new QTimer(this))
{
    m_idPrefix = QLatin1String("sj") + QUuid::createUuid().toString().mid(1, 8);
    connect(m_stream, SIGNAL(connected()), this, SLOT(onStreamConnected()));
    connect(m_stream, SIGNAL(encrypted()), this, SLOT(onStreamEncrypted()));
    connect(m_stream, SIGNAL(streamOpened()), this, SLOT(onStreamOpened()));
    connect(m_stream, SIGNAL(elementReceived(XmlElement)), this, SLOT(onElement(XmlElement)));
    connect(m_stream, SIGNAL(streamClosed()), this, SLOT(onStreamClosed()));
    connect(m_stream, SIGNAL(disconnected(QString)), this, SLOT(onStreamDisconnected(QString)));
    connect(m_stream, SIGNAL(certificateRejected(QString,QString,QString,QString)),
            this, SIGNAL(certificateRejected(QString,QString,QString,QString)));
    m_handshakeTimer->setSingleShot(true);
    m_handshakeTimer->setInterval(HANDSHAKE_TIMEOUT_MS);
    connect(m_handshakeTimer, SIGNAL(timeout()), this, SLOT(onHandshakeTimeout()));
}

QString XmppClient::nextId()
{
    return m_idPrefix + QLatin1Char('-') + QString::number(++m_idCounter);
}

XmlElement XmppClient::iq(const QString &type, const QString &id, const XmlElement &payload)
{
    XmlElement e(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("iq"));
    e.setAttribute(QLatin1String("type"), type);
    e.setAttribute(QLatin1String("id"), id);
    if (!payload.isNull()) e.addChild(payload);
    return e;
}

void XmppClient::setState(State s)
{
    if (m_state == s) return;
    m_state = s;
    emit stateChanged(int(s));
}

void XmppClient::armHandshakeTimer()
{
    m_handshakeTimer->start();
}

void XmppClient::onHandshakeTimeout()
{
    if (m_state != Connected && m_state != Disconnected && m_state != Failed) fail(tr("the server did not answer in time"));
}

void XmppClient::fail(const QString &reason)
{
    m_handshakeTimer->stop();
    m_stream->abort();
    const bool wasConnected = m_state == Connected;
    setState(wasConnected ? Disconnected : Failed);
    // Pending IQ waiters get a timeout-style answer so their owners can clean up.
    const QList<IqCall *> waiters = m_pendingIq.values();
    m_pendingIq.clear();
    for (int i = 0; i < waiters.size(); ++i) waiters.at(i)->settle(XmlElement());
    emit closed(reason);
}

// -- connect / handshake --

void XmppClient::connectToServer(const XmppAccount &account)
{
    if (m_state != Disconnected && m_state != Failed) return;
    m_account = account;
    if (!account.isUsable()) { setState(Failed); emit closed(tr("the account is incomplete")); return; }
    m_domain = Jid::parse(account.jid).domain;
    m_boundJid = Jid();
    m_step = StepNone;
    m_sessionOffered = false;
    setState(Connecting);
    armHandshakeTimer();
    m_stream->connectToHost(account.effectiveHost(), account.port, m_domain);
}

void XmppClient::disconnectFromServer()
{
    m_handshakeTimer->stop();
    if (m_state == Disconnected) return;
    m_stream->close();
    setState(Disconnected);
    const QList<IqCall *> waiters = m_pendingIq.values();
    m_pendingIq.clear();
    for (int i = 0; i < waiters.size(); ++i) waiters.at(i)->settle(XmlElement());
    emit closed(tr("disconnected"));
}

void XmppClient::onStreamConnected()
{
    m_step = StepFeatures;
    armHandshakeTimer();
    m_stream->openStream(m_domain);
}

void XmppClient::onStreamEncrypted()
{
    // Stream restart after TLS.
    m_step = StepFeaturesAfterTls;
    armHandshakeTimer();
    m_stream->openStream(m_domain);
}

void XmppClient::onStreamOpened()
{
}

void XmppClient::onStreamClosed()
{
    if (m_state == Connected) fail(tr("the server closed the stream"));
}

void XmppClient::onStreamDisconnected(const QString &reason)
{
    if (m_state == Disconnected) return;
    fail(reason);
}

void XmppClient::onElement(const XmlElement &e)
{
    if (m_state == Connected) {
        if (e.name() == QLatin1String("message")) handleMessage(e);
        else if (e.name() == QLatin1String("presence")) handlePresence(e);
        else if (e.name() == QLatin1String("iq")) handleIq(e);
        else if (e.is(QLatin1String(Xmpp::STREAM_NS), QLatin1String("error"))) fail(tr("stream error: ") + describeStanzaError(e));
        return;
    }

    // Handshake: the stream is read step by step.
    if (e.is(QLatin1String(Xmpp::STREAM_NS), QLatin1String("error"))) { fail(tr("stream error: ") + describeStanzaError(e)); return; }

    switch (m_step) {
    case StepFeatures:
    case StepFeaturesAfterTls:
    case StepFeaturesAfterSasl:
        if (e.is(QLatin1String(Xmpp::STREAM_NS), QLatin1String("features"))) handleFeatures(e);
        break;
    case StepTlsProceed:
        if (e.is(QLatin1String(Xmpp::TLS_NS), QLatin1String("proceed"))) {
            setState(Securing);
            armHandshakeTimer();
            m_stream->startTls();
        } else {
            fail(tr("the server refused to start TLS"));
        }
        break;
    case StepSasl:
        if (e.is(QLatin1String(Xmpp::SASL_NS), QLatin1String("success"))) {
            m_step = StepFeaturesAfterSasl;
            armHandshakeTimer();
            m_stream->openStream(m_domain);
        } else if (e.is(QLatin1String(Xmpp::SASL_NS), QLatin1String("failure"))) {
            QString why = tr("no reason given");
            const QList<XmlElement> kids = e.children();
            for (int i = 0; i < kids.size(); ++i) {
                const QString n = kids.at(i).name();
                if (n == QLatin1String("text")) continue;
                if (n == QLatin1String("not-authorized")) why = tr("wrong user name or password");
                else if (n == QLatin1String("account-disabled")) why = tr("the account is disabled");
                else if (n == QLatin1String("credentials-expired")) why = tr("the credentials have expired");
                else if (n == QLatin1String("invalid-mechanism")) why = tr("the server rejected PLAIN authentication");
                else why = QString(n).replace(QLatin1Char('-'), QLatin1Char(' '));
                break;
            }
            fail(tr("login rejected: %1").arg(why));
        }
        break;
    case StepBind:
        if (e.name() == QLatin1String("iq") && e.attribute(QLatin1String("id")) == m_pendingBindId) {
            if (e.attribute(QLatin1String("type")) == QLatin1String("error")) { fail(tr("resource binding rejected: %1").arg(describeStanzaError(e))); return; }
            const XmlElement jid = e.child(QLatin1String(Xmpp::BIND_NS), QLatin1String("bind")).child(QLatin1String(Xmpp::BIND_NS), QLatin1String("jid"));
            m_boundJid = Jid::parse(jid.isNull() ? m_account.jid + QLatin1Char('/') + m_account.resource : jid.text());
            if (m_sessionOffered) startSession();
            else finishHandshake();
        }
        break;
    case StepSession:
        if (e.name() == QLatin1String("iq") && e.attribute(QLatin1String("id")) == m_pendingSessionId) finishHandshake();
        break;
    default:
        break;
    }
}

void XmppClient::handleFeatures(const XmlElement &features)
{
    const bool offersTls = !features.child(QLatin1String(Xmpp::TLS_NS), QLatin1String("starttls")).isNull();
    if (m_step == StepFeatures) {
        if (offersTls) {
            m_step = StepTlsProceed;
            armHandshakeTimer();
            m_stream->send(XmlElement(QLatin1String(Xmpp::TLS_NS), QLatin1String("starttls")));
            return;
        }
        if (m_account.requireTls) { fail(tr("the server does not offer TLS")); return; }
        startAuth();
        return;
    }
    if (m_step == StepFeaturesAfterTls) { startAuth(); return; }
    if (m_step == StepFeaturesAfterSasl) {
        m_sessionOffered = !features.child(QLatin1String(Xmpp::SESSION_NS), QLatin1String("session")).isNull();
        startBind();
    }
}

void XmppClient::startAuth()
{
    setState(Authenticating);
    m_step = StepSasl;
    armHandshakeTimer();
    // RFC 4616: authzid NUL authcid NUL password, authzid empty.
    QByteArray payload;
    payload.append('\0');
    payload.append(Jid::parse(m_account.jid).local.toUtf8());
    payload.append('\0');
    payload.append(m_account.password.toUtf8());
    XmlElement auth(QLatin1String(Xmpp::SASL_NS), QLatin1String("auth"), QString::fromLatin1(payload.toBase64()));
    auth.setAttribute(QLatin1String("mechanism"), QLatin1String("PLAIN"));
    m_stream->send(auth);
}

void XmppClient::startBind()
{
    setState(Binding);
    m_step = StepBind;
    armHandshakeTimer();
    m_pendingBindId = nextId();
    XmlElement bind(QLatin1String(Xmpp::BIND_NS), QLatin1String("bind"));
    if (!m_account.resource.isEmpty())
        bind.addChild(XmlElement(QLatin1String(Xmpp::BIND_NS), QLatin1String("resource"), m_account.resource));
    m_stream->send(iq(QLatin1String("set"), m_pendingBindId, bind));
}

void XmppClient::startSession()
{
    // RFC 3921 legacy session: obsolete, but some servers still route nothing without it.
    m_step = StepSession;
    armHandshakeTimer();
    m_pendingSessionId = nextId();
    m_stream->send(iq(QLatin1String("set"), m_pendingSessionId, XmlElement(QLatin1String(Xmpp::SESSION_NS), QLatin1String("session"))));
}

void XmppClient::finishHandshake()
{
    m_handshakeTimer->stop();
    m_step = StepNone;
    setState(Connected);
    emit connectedToServer();
    // Roster first, then initial presence (RFC 6121 section 2.2): the presence of contacts
    // comes back right after our own goes out, and it must find the roster in place.
    m_stream->send(iq(QLatin1String("get"), nextId(), XmlElement(QLatin1String(Xmpp::ROSTER_NS), QLatin1String("query"))));
    m_stream->send(XmlElement(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("presence")));
}

// -- sending --

void XmppClient::sendStanza(const XmlElement &stanza)
{
    if (m_state == Connected) m_stream->send(stanza);
}

QString XmppClient::sendMessage(const QString &toBare, const QString &body)
{
    if (m_state != Connected || toBare.isEmpty() || body.isEmpty()) return QString();
    const QString id = nextId();
    XmlElement m(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("message"));
    m.setAttribute(QLatin1String("to"), toBare);
    m.setAttribute(QLatin1String("type"), QLatin1String("chat"));
    m.setAttribute(QLatin1String("id"), id);
    m.addChild(XmlElement(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("body"), body));
    m_stream->send(m);
    return id;
}

QString XmppClient::sendFileUrl(const QString &toBare, const QString &url)
{
    if (m_state != Connected || toBare.isEmpty() || url.isEmpty()) return QString();
    const QString id = nextId();
    XmlElement m(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("message"));
    m.setAttribute(QLatin1String("to"), toBare);
    m.setAttribute(QLatin1String("type"), QLatin1String("chat"));
    m.setAttribute(QLatin1String("id"), id);
    m.addChild(XmlElement(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("body"), url));
    XmlElement x(QLatin1String(Xmpp::OOB_NS), QLatin1String("x"));
    x.addChild(XmlElement(QLatin1String(Xmpp::OOB_NS), QLatin1String("url"), url));
    m.addChild(x);
    m_stream->send(m);
    return id;
}

void XmppClient::sendPresence(PresenceShow show, const QString &status)
{
    if (m_state != Connected) return;
    XmlElement p(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("presence"));
    if (show == PresenceOffline) p.setAttribute(QLatin1String("type"), QLatin1String("unavailable"));
    else if (!showValue(show).isEmpty()) p.addChild(XmlElement(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("show"), showValue(show)));
    if (!status.isEmpty()) p.addChild(XmlElement(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("status"), status));
    m_stream->send(p);
}

void XmppClient::setContactName(const QString &bareJid, const QString &name)
{
    if (m_state != Connected || bareJid.isEmpty()) return;
    XmlElement item(QLatin1String(Xmpp::ROSTER_NS), QLatin1String("item"));
    item.setAttribute(QLatin1String("jid"), bareJid);
    if (!name.isEmpty()) item.setAttribute(QLatin1String("name"), name);
    XmlElement query(QLatin1String(Xmpp::ROSTER_NS), QLatin1String("query"));
    query.addChild(item);
    m_stream->send(iq(QLatin1String("set"), nextId(), query));
}

void XmppClient::removeContact(const QString &bareJid)
{
    if (m_state != Connected || bareJid.isEmpty()) return;
    XmlElement item(QLatin1String(Xmpp::ROSTER_NS), QLatin1String("item"));
    item.setAttribute(QLatin1String("jid"), bareJid);
    item.setAttribute(QLatin1String("subscription"), QLatin1String("remove"));
    XmlElement query(QLatin1String(Xmpp::ROSTER_NS), QLatin1String("query"));
    query.addChild(item);
    m_stream->send(iq(QLatin1String("set"), nextId(), query));
}

void XmppClient::addContact(const QString &bareJid, const QString &name)
{
    // The roster item first so the contact shows up while the request is unanswered.
    setContactName(bareJid, name);
    requestSubscription(bareJid);
}

void XmppClient::requestSubscription(const QString &bareJid)
{
    if (m_state != Connected || bareJid.isEmpty()) return;
    XmlElement p(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("presence"));
    p.setAttribute(QLatin1String("to"), bareJid);
    p.setAttribute(QLatin1String("type"), QLatin1String("subscribe"));
    m_stream->send(p);
}

void XmppClient::answerSubscription(const QString &bareJid, bool accepted, bool subscribeBack)
{
    if (m_state != Connected || bareJid.isEmpty()) return;
    XmlElement p(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("presence"));
    p.setAttribute(QLatin1String("to"), bareJid);
    p.setAttribute(QLatin1String("type"), QLatin1String(accepted ? "subscribed" : "unsubscribed"));
    m_stream->send(p);
    // Subscriptions are one-directional: also ask for theirs, or they stay "offline" here.
    if (accepted && subscribeBack) requestSubscription(bareJid);
}

IqCall *XmppClient::request(const QString &to, const QString &type, const XmlElement &payload, int timeoutMs)
{
    const QString id = nextId();
    IqCall *call = new IqCall(id, timeoutMs, this);
    if (m_state != Connected) {
        QTimer::singleShot(0, call, SLOT(onTimeout()));
        return call;
    }
    m_pendingIq.insert(id, call);
    XmlElement stanza = iq(type, id, payload);
    if (!to.isEmpty()) stanza.setAttribute(QLatin1String("to"), to);
    m_stream->send(stanza);
    return call;
}

void XmppClient::deliverMessage(const XmppMessage &message)
{
    emit messageReceived(message);
}

// -- incoming stanzas --

void XmppClient::handleMessage(const XmlElement &stanza)
{
    const QString type = stanza.attribute(QLatin1String("type"));
    if (type == QLatin1String("error") || type == QLatin1String("groupchat")) return;

    if (m_hook && m_hook->handleIncomingMessage(stanza)) return;

    const XmlElement body = stanza.child(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("body"));
    if (body.isNull() || body.text().isEmpty()) return;   // receipts, chat states, ...
    const QString from = Jid::bareOf(stanza.attribute(QLatin1String("from")));
    if (from.isEmpty()) return;
    XmppMessage m(from, body.text(), false);
    m.id = stanza.attribute(QLatin1String("id"));
    emit messageReceived(m);
}

void XmppClient::handlePresence(const XmlElement &stanza)
{
    const QString from = Jid::bareOf(stanza.attribute(QLatin1String("from")));
    if (from.isEmpty()) return;
    if (m_boundJid.isValid() && from.compare(m_boundJid.bare(), Qt::CaseInsensitive) == 0) return;   // our other clients

    const QString type = stanza.attribute(QLatin1String("type"));
    if (type == QLatin1String("subscribe")) { emit subscriptionRequested(from); return; }
    if (type == QLatin1String("subscribed") || type == QLatin1String("unsubscribe") ||
        type == QLatin1String("unsubscribed") || type == QLatin1String("error")) return;   // roster push follows

    RosterItem item;
    item.jid = from;
    item.presence = type == QLatin1String("unavailable") ? PresenceOffline
                  : parseShow(stanza.child(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("show")).text());
    item.status = stanza.child(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("status")).text();
    emit presenceChanged(item);
}

void XmppClient::handleIq(const XmlElement &stanza)
{
    const QString id = stanza.attribute(QLatin1String("id"));
    const QString type = stanza.attribute(QLatin1String("type"));
    if (!id.isEmpty() && (type == QLatin1String("result") || type == QLatin1String("error"))) {
        IqCall *waiter = m_pendingIq.take(id);
        if (waiter) { waiter->settle(stanza); return; }
    }

    const XmlElement query = stanza.child(QLatin1String(Xmpp::ROSTER_NS), QLatin1String("query"));
    if (!query.isNull()) {
        QList<RosterItem> items;
        const QList<XmlElement> kids = query.childrenNamed(QLatin1String(Xmpp::ROSTER_NS), QLatin1String("item"));
        for (int i = 0; i < kids.size(); ++i) {
            const XmlElement &el = kids.at(i);
            const QString jid = Jid::bareOf(el.attribute(QLatin1String("jid")));
            if (jid.isEmpty()) continue;
            RosterItem item;
            item.jid = jid;
            item.name = el.attribute(QLatin1String("name"));
            item.subscription = el.attribute(QLatin1String("subscription"));
            items.append(item);   // "remove" items are passed through with that subscription
        }
        if (type == QLatin1String("set") && !id.isEmpty()) {
            // Acknowledge the roster push.
            XmlElement ack = iq(QLatin1String("result"), id, XmlElement());
            m_stream->send(ack);
        }
        emit rosterReceived(items);
        return;
    }

    // Anything else we do not implement: answer get/set with feature-not-implemented.
    if ((type == QLatin1String("get") || type == QLatin1String("set")) && !id.isEmpty()) {
        XmlElement err = iq(QLatin1String("error"), id, XmlElement());
        const QString from = stanza.attribute(QLatin1String("from"));
        if (!from.isEmpty()) err.setAttribute(QLatin1String("to"), from);
        XmlElement error(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("error"));
        error.setAttribute(QLatin1String("type"), QLatin1String("cancel"));
        error.addChild(XmlElement(QLatin1String(Xmpp::STANZA_ERROR_NS), QLatin1String("feature-not-implemented")));
        err.addChild(error);
        m_stream->send(err);
    }
}

// -- helpers --

QString XmppClient::showValue(PresenceShow show)
{
    switch (show) {
    case PresenceChat: return QLatin1String("chat");
    case PresenceAway: return QLatin1String("away");
    case PresenceExtendedAway: return QLatin1String("xa");
    case PresenceDnd: return QLatin1String("dnd");
    default: return QString();
    }
}

PresenceShow XmppClient::parseShow(const QString &show)
{
    if (show == QLatin1String("chat")) return PresenceChat;
    if (show == QLatin1String("away")) return PresenceAway;
    if (show == QLatin1String("xa")) return PresenceExtendedAway;
    if (show == QLatin1String("dnd")) return PresenceDnd;
    return PresenceOnline;
}

QString XmppClient::describeStanzaError(const XmlElement &stanza)
{
    XmlElement error = stanza.child(QLatin1String(Xmpp::CLIENT_NS), QLatin1String("error"));
    if (error.isNull()) error = stanza;
    QString condition, text;
    const QList<XmlElement> kids = error.children();
    for (int i = 0; i < kids.size(); ++i) {
        if (kids.at(i).name() == QLatin1String("text")) text = kids.at(i).text();
        else if (condition.isEmpty()) condition = kids.at(i).name();
    }
    if (!text.isEmpty()) return text;
    if (!condition.isEmpty()) return condition.replace(QLatin1Char('-'), QLatin1Char(' '));
    return QObject::tr("unknown error");
}
