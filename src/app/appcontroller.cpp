// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "appcontroller.h"
#include "contactsmodel.h"
#include "messagesmodel.h"
#include "messagestore.h"
#include "mediacache.h"
#include "networkmanager.h"
#include "imageuploader.h"
#include "../omemo/omemomanager.h"

#include <QApplication>
#include <QBuffer>
#include <QClipboard>
#include <QDeclarativeView>
#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#include <QImageReader>
#include <QLocale>
#include <QNetworkConfigurationManager>
#include <QNetworkSession>
#include <QTimer>
#include <QUrl>
#include <QUuid>
#include <QDebug>

#ifndef APP_VERSION
#define APP_VERSION 0.0.0
#endif
#define SJ_STR_(x) #x
#define SJ_STR(x) SJ_STR_(x)

namespace {
const int MaxUploadEdge = 1280;
const int ReconnectMaxMs = 60 * 1000;
}

AppController::AppController(QObject *parent)
    : QObject(parent),
      m_settings(QLatin1String("SimpleJabber"), QLatin1String("SimpleJabber")),
      m_net(new NetworkManager(this)), m_client(new XmppClient(this)), m_omemo(0),
      m_netMgr(0), m_netSession(0), m_reconnect(new QTimer(this)), m_view(0),
      m_state(QLatin1String("login")), m_wantOnline(false), m_certPrompt(false), m_reconnectDelay(5000),
      m_busy(false), m_started(false)
{
    m_store = new MessageStore(dataDir() + QLatin1String("/messages"));
    m_media = new MediaCache(m_net, QDesktopServices::storageLocation(QDesktopServices::CacheLocation) + QLatin1String("/SimpleJabber"), this);
    m_contacts = new ContactsModel(this);
    m_chat = new MessagesModel(this);

    connect(m_client, SIGNAL(stateChanged(int)), this, SLOT(onClientState(int)));
    connect(m_client, SIGNAL(connectedToServer()), this, SLOT(onConnected()));
    connect(m_client, SIGNAL(closed(QString)), this, SLOT(onClosed(QString)));
    connect(m_client, SIGNAL(messageReceived(XmppMessage)), this, SLOT(onMessageReceived(XmppMessage)));
    connect(m_client, SIGNAL(rosterReceived(QList<RosterItem>)), this, SLOT(onRosterReceived(QList<RosterItem>)));
    connect(m_client, SIGNAL(presenceChanged(RosterItem)), this, SLOT(onPresenceChanged(RosterItem)));
    connect(m_client, SIGNAL(subscriptionRequested(QString)), this, SLOT(onSubscriptionRequested(QString)));
    connect(m_client, SIGNAL(certificateRejected(QString,QString,QString,QString)),
            this, SLOT(onCertificateRejected(QString,QString,QString,QString)));
    connect(m_media, SIGNAL(ready(QString,QString)), this, SLOT(onMediaReady(QString,QString)));
    connect(m_media, SIGNAL(failed(QString,QString)), this, SLOT(onMediaFailed(QString,QString)));

    m_reconnect->setSingleShot(true);
    connect(m_reconnect, SIGNAL(timeout()), this, SLOT(onReconnectTimer()));

    // Certificate pins the user accepted earlier.
    m_settings.beginGroup(QLatin1String("pins"));
    const QStringList hosts = m_settings.childKeys();
    for (int i = 0; i < hosts.size(); ++i) XmppStream::setPinnedCertificate(hosts.at(i), m_settings.value(hosts.at(i)).toString());
    m_settings.endGroup();

    loadAccount();
}

AppController::~AppController()
{
    delete m_store;
}

// -- small state --

QString AppController::dataDir() const
{
    QString dir = QDesktopServices::storageLocation(QDesktopServices::DataLocation);
    if (dir.isEmpty()) dir = QDir::homePath() + QLatin1String("/.simplejabber");
    return dir;
}

QString AppController::omemoDirFor(const QString &jid) const
{
    return dataDir() + QLatin1String("/omemo/") + QString::fromLatin1(jid.toLower().toUtf8().toHex());
}

QString AppController::version() const { return QLatin1String(SJ_STR(APP_VERSION)); }
bool AppController::sslSupported() const { return NetworkManager::sslSupported(); }
bool AppController::isConnected() const { return m_client->isConnected(); }

QString AppController::language() const { return m_settings.value(QLatin1String("ui/language")).toString(); }

void AppController::setLanguage(const QString &lang)
{
    if (language() == lang) return;
    m_settings.setValue(QLatin1String("ui/language"), lang);
    emit settingsChanged();
    setNotice(tr("The language changes the next time the app starts."));
}

QString AppController::effectiveLanguage(const QSettings &settings)
{
    const QString chosen = settings.value(QLatin1String("ui/language")).toString();
    if (!chosen.isEmpty()) return chosen;
    return QLocale::system().name().left(2).toLower() == QLatin1String("ru") ? QString::fromLatin1("ru") : QString::fromLatin1("en");
}

void AppController::setState(const QString &s)
{
    if (m_state == s) return;
    m_state = s;
    emit stateChanged();
}

QString AppController::stateText() const
{
    if (m_state == QLatin1String("online")) return tr("online");
    if (m_state == QLatin1String("connecting")) {
        switch (m_client->state()) {
        case XmppClient::Securing: return tr("securing the connection...");
        case XmppClient::Authenticating: return tr("signing in...");
        case XmppClient::Binding: return tr("almost there...");
        default: return tr("connecting...");
        }
    }
    if (m_state == QLatin1String("offline")) return m_lastError.isEmpty() ? tr("offline") : m_lastError;
    return QString();
}

void AppController::setNotice(const QString &n)
{
    m_notice = n;
    emit noticeChanged();
}

void AppController::clearNotice() { setNotice(QString()); }

void AppController::setBusy(bool b)
{
    if (m_busy == b) return;
    m_busy = b;
    emit busyChanged();
}

bool AppController::omemoReady() const { return m_omemo && m_omemo->isEnabled(); }
QString AppController::ownFingerprint() const { return m_omemo ? m_omemo->ownFingerprint() : QString(); }
QString AppController::ownDeviceId() const { return m_omemo ? QString::number(m_omemo->ownDeviceId()) : QString(); }

// -- account --

void AppController::loadAccount()
{
    m_account.jid = m_settings.value(QLatin1String("account/jid")).toString();
    m_account.password = m_settings.value(QLatin1String("account/password")).toString();
    m_account.host = m_settings.value(QLatin1String("account/host")).toString();
    m_account.port = quint16(m_settings.value(QLatin1String("account/port"), Xmpp::DEFAULT_PORT).toInt());
    m_account.resource = m_settings.value(QLatin1String("account/resource"), QLatin1String("SimpleJabber")).toString();
    emit accountChanged();
}

void AppController::storeAccount()
{
    m_settings.setValue(QLatin1String("account/jid"), m_account.jid);
    m_settings.setValue(QLatin1String("account/password"), m_account.password);
    m_settings.setValue(QLatin1String("account/host"), m_account.host);
    m_settings.setValue(QLatin1String("account/port"), int(m_account.port));
    m_settings.setValue(QLatin1String("account/resource"), m_account.resource);
    m_settings.sync();
    emit accountChanged();
}

void AppController::saveAccount(const QString &jid, const QString &password, const QString &host, int port)
{
    m_account.jid = Jid::parse(jid).bare();
    m_account.password = password;
    m_account.host = host.trimmed();
    m_account.port = quint16(port > 0 ? port : Xmpp::DEFAULT_PORT);
    storeAccount();
}

void AppController::signIn(const QString &jid, const QString &password, const QString &host, int port)
{
    const Jid parsed = Jid::parse(jid);
    if (!parsed.isValid() || parsed.local.isEmpty() || password.isEmpty()) {
        setNotice(tr("Enter a full Jabber ID (user@server) and the password."));
        return;
    }
    saveAccount(jid, password, host, port);
    m_wantOnline = true;
    m_reconnectDelay = 5000;
    connectSession();
}

void AppController::connectNow()
{
    if (!hasAccount()) { setState(QLatin1String("login")); return; }
    m_wantOnline = true;
    m_reconnectDelay = 5000;
    m_reconnect->stop();
    connectSession();
}

void AppController::disconnectNow()
{
    m_wantOnline = false;
    m_reconnect->stop();
    stopOmemo();
    m_client->disconnectFromServer();
    m_lastError.clear();
    setState(QLatin1String("offline"));
}

void AppController::signOut()
{
    disconnectNow();
    m_settings.remove(QLatin1String("account"));
    m_settings.sync();
    m_account = XmppAccount();
    m_contacts->clear();
    m_chat->close();
    m_requests.clear();
    emit requestsChanged();
    emit accountChanged();
    setState(QLatin1String("login"));
}

// -- start-up / network --

void AppController::start()
{
    if (m_started) return;
    m_started = true;
    if (!hasAccount()) { setState(QLatin1String("login")); return; }
    loadKnownChats();
    setState(QLatin1String("offline"));

    // On the phone: open the default access point once, then connect.
    m_netMgr = new QNetworkConfigurationManager(this);
    const QNetworkConfiguration cfg = m_netMgr->defaultConfiguration();
    if (cfg.isValid() && (m_netMgr->capabilities() & QNetworkConfigurationManager::NetworkSessionRequired)) {
        NetworkManager::setDefaultConfiguration(cfg);
        m_net->setConfiguration(cfg);
        m_netSession = new QNetworkSession(cfg, this);
        connect(m_netSession, SIGNAL(opened()), this, SLOT(onNetworkOpened()));
        connect(m_netSession, SIGNAL(error(QNetworkSession::SessionError)), this, SLOT(onNetworkError()));
        m_wantOnline = true;
        setState(QLatin1String("connecting"));
        m_netSession->open();
        return;
    }
    connectNow();
}

void AppController::onNetworkOpened() { connectSession(); }
void AppController::onNetworkError() { qWarning() << "network session error"; connectSession(); }

void AppController::connectSession()
{
    if (!hasAccount()) return;
    if (m_client->state() != XmppClient::Disconnected && m_client->state() != XmppClient::Failed) return;
    m_certPrompt = false;
    emit certChanged();
    m_lastError.clear();
    setState(QLatin1String("connecting"));
    m_client->connectToServer(m_account);
}

void AppController::scheduleReconnect()
{
    if (!m_wantOnline || m_certPrompt) return;
    m_reconnect->start(m_reconnectDelay);
    m_reconnectDelay = qMin(m_reconnectDelay * 2, ReconnectMaxMs);
}

void AppController::onReconnectTimer()
{
    if (m_wantOnline) connectSession();
}

void AppController::onClientState(int)
{
    emit stateChanged();
}

void AppController::onConnected()
{
    m_reconnectDelay = 5000;
    m_lastError.clear();
    setState(QLatin1String("online"));
    startOmemo();
}

void AppController::onClosed(const QString &reason)
{
    stopOmemo();
    m_pendingPresence.clear();
    // Everyone is offline once the session is gone.
    const QList<QString> jids = m_contacts->jids();
    for (int i = 0; i < jids.size(); ++i) {
        Chat c = m_contacts->chat(jids.at(i));
        if (c.presence != PresenceOffline) { c.presence = PresenceOffline; c.status.clear(); m_contacts->update(c); }
    }
    m_lastError = reason;
    setState(QLatin1String("offline"));
    if (m_wantOnline && !m_certPrompt) {
        // Wrong credentials never fix themselves; anything else gets retried.
        if (reason.contains(QLatin1String("login rejected"), Qt::CaseInsensitive)) { m_wantOnline = false; setNotice(reason); }
        else scheduleReconnect();
    }
    emit stateChanged();
}

void AppController::onCertificateRejected(const QString &host, const QString &fingerprint, const QString &subject, const QString &errors)
{
    m_certPrompt = true;
    m_certHost = host;
    m_certFingerprint = fingerprint;
    m_certSubject = subject;
    m_certErrors = errors;
    emit certChanged();
}

void AppController::acceptCertificate()
{
    if (m_certFingerprint.isEmpty()) return;
    XmppStream::setPinnedCertificate(m_certHost, m_certFingerprint);
    m_settings.setValue(QLatin1String("pins/") + m_certHost, m_certFingerprint);
    m_settings.sync();
    m_certPrompt = false;
    emit certChanged();
    connectNow();
}

void AppController::dismissCertificate()
{
    m_certPrompt = false;
    m_wantOnline = false;
    emit certChanged();
    setState(QLatin1String("offline"));
}

// -- OMEMO --

void AppController::startOmemo()
{
    stopOmemo();
    m_omemo = new OmemoManager(m_client, m_client->boundJid().bare(), omemoDirFor(m_client->boundJid().bare()), this);
    connect(m_omemo, SIGNAL(enabledChanged(bool)), this, SLOT(onOmemoEnabled(bool)));
    connect(m_omemo, SIGNAL(sendFinished(QString,bool,QString)), this, SLOT(onOmemoSendFinished(QString,bool,QString)));
    m_omemo->enable();
    emit omemoChanged();
}

void AppController::stopOmemo()
{
    if (!m_omemo) return;
    m_omemo->disable();
    m_omemo->deleteLater();
    m_omemo = 0;
    emit omemoChanged();
}

void AppController::onOmemoEnabled(bool enabled)
{
    if (!enabled) setNotice(tr("OMEMO could not be set up on this server."));
    emit omemoChanged();
}

bool AppController::chatOmemo(const QString &jid) const
{
    return m_settings.value(QLatin1String("omemo/") + QString::fromLatin1(jid.toLower().toUtf8().toHex()), false).toBool();
}

void AppController::setChatOmemo(const QString &jid, bool on)
{
    if (on && !omemoReady()) { setNotice(tr("OMEMO is not ready yet - try again in a moment.")); return; }
    m_settings.setValue(QLatin1String("omemo/") + QString::fromLatin1(jid.toLower().toUtf8().toHex()), on);
    Chat c = m_contacts->chat(jid);
    c.jid = jid.toLower();
    c.omemo = on;
    m_contacts->update(c);
    setNotice(on ? tr("Messages to this contact are now OMEMO encrypted.") : tr("OMEMO turned off for this contact."));
}

QString AppController::contactFingerprint(const QString &jid)
{
    return m_omemo ? m_omemo->contactFingerprint(jid) : QString();
}

// -- chats --

void AppController::loadKnownChats()
{
    // Conversations with stored history show up before the roster arrives (and even when
    // the contact is no longer on it).
    QDir dir(dataDir() + QLatin1String("/messages"));
    const QStringList files = dir.entryList(QStringList() << QLatin1String("*.dat"), QDir::Files);
    for (int i = 0; i < files.size(); ++i) {
        const QString jid = QString::fromUtf8(QByteArray::fromHex(files.at(i).left(files.at(i).size() - 4).toLatin1()));
        if (jid.isEmpty() || !jid.contains(QLatin1Char('@'))) continue;
        Chat c = m_contacts->chat(jid);
        c.jid = jid;
        c.lastMessage = m_store->last(jid).body;
        c.omemo = chatOmemo(jid);
        m_contacts->update(c);
    }
}

void AppController::openChat(const QString &jid)
{
    Chat c = m_contacts->ensure(jid);
    c.unread = 0;
    c.omemo = chatOmemo(jid);
    m_contacts->update(c);
    const QList<XmppMessage> history = m_store->load(jid);
    m_chat->open(jid, history);
    for (int i = 0; i < history.size(); ++i) requestImagesFor(history.at(i));
}

void AppController::closeChat()
{
    m_chat->close();
}

QString AppController::newMessageId() const
{
    return QUuid::createUuid().toString().remove(QLatin1Char('{')).remove(QLatin1Char('}')).remove(QLatin1Char('-'));
}

void AppController::storeMessage(const XmppMessage &m)
{
    m_store->append(m.contactJid, m);
    Chat c = m_contacts->ensure(m.contactJid);
    c.lastMessage = m.body;
    m_contacts->update(c);
}

void AppController::requestImagesFor(const XmppMessage &m)
{
    if (!MessagesModel::isImageMessage(m.body)) return;
    const QString source = m.body.trimmed();
    const QString cached = m_media->cachedPath(source);
    if (!cached.isEmpty()) m_chat->setImagePath(source, QUrl::fromLocalFile(cached).toString());
    else m_media->fetch(source);
}

void AppController::onMediaReady(const QString &source, const QString &path)
{
    m_chat->setImagePath(source, QUrl::fromLocalFile(path).toString());
}

void AppController::onMediaFailed(const QString &source, const QString &error)
{
    Q_UNUSED(source);
    qWarning() << "picture download failed:" << error;
}

void AppController::sendText(const QString &text)
{
    const QString body = text.trimmed();
    const QString jid = m_chat->jid();
    if (body.isEmpty() || jid.isEmpty()) return;
    if (!m_client->isConnected()) { setNotice(tr("Not connected.")); return; }

    XmppMessage m(jid, body, true);
    if (chatOmemo(jid)) {
        if (!omemoReady()) { setNotice(tr("OMEMO is not ready yet.")); return; }
        m.id = newMessageId();
        m.encrypted = true;
        m_chat->append(m, true);
        m_omemo->sendEncrypted(jid, body, m.id);
        return;
    }
    m.id = m_client->sendMessage(jid, body);
    if (m.id.isEmpty()) { setNotice(tr("Not connected.")); return; }
    m_chat->append(m);
    storeMessage(m);
}

void AppController::onOmemoSendFinished(const QString &id, bool ok, const QString &error)
{
    m_chat->markSent(id, ok);
    if (!ok) { setNotice(tr("Not sent: %1").arg(error)); return; }
    // The pending bubble is in the model; persist it now that it went out.
    for (int i = m_chat->rowCount() - 1; i >= 0; --i) {
        const QVariantMap row = m_chat->get(i);
        if (row.value(QLatin1String("messageId")).toString() != id) continue;
        XmppMessage m(m_chat->jid(), row.value(QLatin1String("body")).toString(), true);
        m.id = id;
        m.encrypted = true;
        storeMessage(m);
        break;
    }
}

QString AppController::pickImage()
{
    QString dir = QDesktopServices::storageLocation(QDesktopServices::PicturesLocation);
#ifdef Q_OS_SYMBIAN
    dir = QDir(QLatin1String("E:/")).exists() ? QLatin1String("E:/Images") : QLatin1String("C:/Data/Images");
#endif
    return QFileDialog::getOpenFileName(m_view, tr("Choose a picture"), dir, tr("Pictures (*.jpg *.jpeg *.png)"));
}

void AppController::sendImageFile(const QString &path)
{
    const QString jid = m_chat->jid();
    if (path.isEmpty() || jid.isEmpty()) return;
    if (!m_client->isConnected()) { setNotice(tr("Not connected.")); return; }

    // Decode at a bounded size and re-encode as JPEG: a phone camera picture is far
    // bigger than a chat needs, and the upload quota is usually small.
    QImageReader reader(path);
    QSize size = reader.size();
    if (size.isValid() && (size.width() > MaxUploadEdge || size.height() > MaxUploadEdge)) {
        size.scale(MaxUploadEdge, MaxUploadEdge, Qt::KeepAspectRatio);
        reader.setScaledSize(size);
    }
    const QImage img = reader.read();
    if (img.isNull()) { setNotice(tr("Could not read the picture.")); return; }
    QByteArray bytes;
    QBuffer buf(&bytes);
    buf.open(QIODevice::WriteOnly);
    img.save(&buf, "JPEG", 85);

    const bool encrypt = chatOmemo(jid);
    if (encrypt && !omemoReady()) { setNotice(tr("OMEMO is not ready yet.")); return; }
    setBusy(true);
    ImageUploader *up = new ImageUploader(m_client, m_net, m_uploadService, bytes,
                                          QLatin1String("photo_") + QString::number(QDateTime::currentDateTime().toTime_t()) + QLatin1String(".jpg"),
                                          QLatin1String("image/jpeg"), encrypt, this);
    up->setProperty("jid", jid);
    up->setProperty("plain", bytes);
    connect(up, SIGNAL(finished(bool,QString,QString)), this, SLOT(onUploadFinished(bool,QString,QString)));
    up->start();
}

void AppController::onUploadFinished(bool ok, const QString &url, const QString &error)
{
    setBusy(false);
    ImageUploader *up = qobject_cast<ImageUploader *>(sender());
    if (!up) return;
    if (!ok) { setNotice(error); return; }
    m_uploadService = up->service();
    const QString jid = up->property("jid").toString();
    const QByteArray plain = up->property("plain").toByteArray();

    // The picture we just sent shows from the cache, no download needed.
    const QString cached = m_media->seed(url, plain);
    XmppMessage m(jid, url, true);
    if (OmemoManager::isAesGcmUrl(url)) {
        m.id = newMessageId();
        m.encrypted = true;
        if (m_chat->jid() == jid) { m_chat->append(m, true); m_chat->setImagePath(url, QUrl::fromLocalFile(cached).toString()); }
        m_omemo->sendEncrypted(jid, url, m.id);
        return;
    }
    m.id = m_client->sendFileUrl(jid, url);
    if (m.id.isEmpty()) { setNotice(tr("Upload finished but the message could not be sent.")); return; }
    if (m_chat->jid() == jid) { m_chat->append(m); m_chat->setImagePath(url, QUrl::fromLocalFile(cached).toString()); }
    storeMessage(m);
}

void AppController::clearHistory(const QString &jid)
{
    m_store->clear(jid);
    if (m_chat->jid() == jid.toLower()) m_chat->open(jid, QList<XmppMessage>());
    Chat c = m_contacts->chat(jid);
    if (!c.jid.isEmpty()) { c.lastMessage.clear(); m_contacts->update(c); }
}

// -- incoming --

void AppController::onMessageReceived(const XmppMessage &message)
{
    XmppMessage m = message;
    m.contactJid = m.contactJid.toLower();
    Chat c = m_contacts->ensure(m.contactJid);
    c.lastMessage = m.body;
    const bool open = m_chat->jid() == m.contactJid;
    if (!open) c.unread += 1;
    m_contacts->update(c);
    m_store->append(m.contactJid, m);
    if (open) {
        m_chat->append(m);
        requestImagesFor(m);
    } else {
        emit newMessage(m.contactJid);
    }
}

void AppController::onRosterReceived(const QList<RosterItem> &items)
{
    for (int i = 0; i < items.size(); ++i) {
        const RosterItem &it = items.at(i);
        if (it.subscription == QLatin1String("remove")) {
            Chat c = m_contacts->chat(it.jid);
            if (c.jid.isEmpty()) continue;
            c.inRoster = false;
            c.presence = PresenceOffline;
            m_contacts->update(c);
            continue;
        }
        Chat c = m_contacts->ensure(it.jid);
        c.name = it.name;
        c.subscription = it.subscription;
        c.inRoster = true;
        c.omemo = chatOmemo(it.jid);
        if (c.lastMessage.isEmpty()) c.lastMessage = m_store->last(it.jid).body;
        if (m_pendingPresence.contains(c.jid)) {
            const RosterItem p = m_pendingPresence.take(c.jid);
            c.presence = p.presence;
            c.status = p.status;
        }
        m_contacts->update(c);
    }
}

void AppController::onPresenceChanged(const RosterItem &item)
{
    Chat c = m_contacts->chat(item.jid);
    if (c.jid.isEmpty()) {
        // Not on the list (yet): keep it for when the roster arrives.
        m_pendingPresence.insert(item.jid.toLower(), item);
        return;
    }
    c.presence = item.presence;
    c.status = item.status;
    m_contacts->update(c);
}

void AppController::onSubscriptionRequested(const QString &jid)
{
    if (m_requests.contains(jid, Qt::CaseInsensitive)) return;
    m_requests.append(jid.toLower());
    emit requestsChanged();
}

// -- roster actions --

void AppController::addContact(const QString &jidIn)
{
    const Jid j = Jid::parse(jidIn);
    if (!j.isValid() || j.local.isEmpty()) { setNotice(tr("Enter a full Jabber ID, like someone@example.com.")); return; }
    if (!m_client->isConnected()) { setNotice(tr("Not connected.")); return; }
    m_contacts->ensure(j.bare());
    m_client->addContact(j.bare(), QString());
}

void AppController::renameContact(const QString &jid, const QString &name)
{
    Chat c = m_contacts->chat(jid);
    if (c.jid.isEmpty()) return;
    c.name = name.trimmed();
    m_contacts->update(c);
    m_client->setContactName(jid, c.name);
}

void AppController::removeContact(const QString &jid)
{
    m_client->removeContact(jid);
    m_contacts->remove(jid);
    m_store->clear(jid);
    if (m_chat->jid() == jid.toLower()) m_chat->close();
}

void AppController::acceptRequest(const QString &jid)
{
    m_requests.removeAll(jid.toLower());
    emit requestsChanged();
    m_contacts->ensure(jid);
    m_client->answerSubscription(jid, true, true);
}

void AppController::declineRequest(const QString &jid)
{
    m_requests.removeAll(jid.toLower());
    emit requestsChanged();
    m_client->answerSubscription(jid, false, false);
}

// -- host services --

void AppController::openUrl(const QString &url)
{
    if (!url.isEmpty()) QDesktopServices::openUrl(QUrl::fromEncoded(url.toUtf8()));
}

void AppController::copyText(const QString &text)
{
    QApplication::clipboard()->setText(text);
    setNotice(tr("Copied"));
}
