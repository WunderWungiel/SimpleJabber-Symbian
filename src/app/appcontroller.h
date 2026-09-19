// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// Process-wide state, exposed to QML as "app": the account, the one XMPP session and its
// OMEMO manager, the contact and chat models, message history, picture cache and the
// host services QML cannot do itself.
#ifndef SJ_APPCONTROLLER_H
#define SJ_APPCONTROLLER_H

#include "../xmpp/xmppclient.h"

#include <QObject>
#include <QHash>
#include <QSettings>
#include <QStringList>

class OmemoManager;
class NetworkManager;
class MessageStore;
class MediaCache;
class ContactsModel;
class MessagesModel;
class QNetworkConfigurationManager;
class QNetworkSession;
class QTimer;
class QDeclarativeView;

class AppController : public QObject
{
    Q_OBJECT
    /// "login" (no account yet), "offline", "connecting", "online".
    Q_PROPERTY(QString state READ state NOTIFY stateChanged)
    Q_PROPERTY(QString stateText READ stateText NOTIFY stateChanged)
    Q_PROPERTY(bool connected READ isConnected NOTIFY stateChanged)
    Q_PROPERTY(bool hasAccount READ hasAccount NOTIFY accountChanged)
    Q_PROPERTY(QString accountJid READ accountJid NOTIFY accountChanged)
    Q_PROPERTY(QString accountPassword READ accountPassword NOTIFY accountChanged)
    Q_PROPERTY(QString accountHost READ accountHost NOTIFY accountChanged)
    Q_PROPERTY(int accountPort READ accountPort NOTIFY accountChanged)
    Q_PROPERTY(QString notice READ notice NOTIFY noticeChanged)
    Q_PROPERTY(QString lastError READ lastError NOTIFY stateChanged)
    Q_PROPERTY(bool omemoReady READ omemoReady NOTIFY omemoChanged)
    Q_PROPERTY(QString ownFingerprint READ ownFingerprint NOTIFY omemoChanged)
    Q_PROPERTY(QString ownDeviceId READ ownDeviceId NOTIFY omemoChanged)
    Q_PROPERTY(ContactsModel *contacts READ contacts CONSTANT)
    Q_PROPERTY(MessagesModel *chat READ chat CONSTANT)
    Q_PROPERTY(QStringList requests READ requests NOTIFY requestsChanged)
    Q_PROPERTY(bool certPrompt READ certPrompt NOTIFY certChanged)
    Q_PROPERTY(QString certHost READ certHost NOTIFY certChanged)
    Q_PROPERTY(QString certFingerprint READ certFingerprint NOTIFY certChanged)
    Q_PROPERTY(QString certSubject READ certSubject NOTIFY certChanged)
    Q_PROPERTY(QString certErrors READ certErrors NOTIFY certChanged)
    Q_PROPERTY(QString version READ version CONSTANT)
    Q_PROPERTY(bool sslSupported READ sslSupported CONSTANT)
    Q_PROPERTY(QString language READ language WRITE setLanguage NOTIFY settingsChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
public:
    explicit AppController(QObject *parent = 0);
    ~AppController();

    void setView(QDeclarativeView *view) { m_view = view; }
    void start();
    static QString effectiveLanguage(const QSettings &settings);

    QString state() const { return m_state; }
    QString stateText() const;
    bool isConnected() const;
    bool hasAccount() const { return m_account.isUsable(); }
    QString accountJid() const { return m_account.jid; }
    QString accountPassword() const { return m_account.password; }
    QString accountHost() const { return m_account.host; }
    int accountPort() const { return m_account.port; }
    QString notice() const { return m_notice; }
    QString lastError() const { return m_lastError; }
    bool omemoReady() const;
    QString ownFingerprint() const;
    QString ownDeviceId() const;
    ContactsModel *contacts() const { return m_contacts; }
    MessagesModel *chat() const { return m_chat; }
    QStringList requests() const { return m_requests; }
    bool certPrompt() const { return m_certPrompt; }
    QString certHost() const { return m_certHost; }
    QString certFingerprint() const { return m_certFingerprint; }
    QString certSubject() const { return m_certSubject; }
    QString certErrors() const { return m_certErrors; }
    QString version() const;
    bool sslSupported() const;
    QString language() const;
    void setLanguage(const QString &lang);
    bool busy() const { return m_busy; }

public slots:
    // account / session
    void signIn(const QString &jid, const QString &password, const QString &host, int port);
    void saveAccount(const QString &jid, const QString &password, const QString &host, int port);
    void connectNow();
    void disconnectNow();
    void signOut();
    void acceptCertificate();
    void dismissCertificate();
    // chats
    void openChat(const QString &jid);
    void closeChat();
    void sendText(const QString &text);
    void sendImageFile(const QString &path);
    QString pickImage();
    void setChatOmemo(const QString &jid, bool on);
    QString contactFingerprint(const QString &jid);
    void clearHistory(const QString &jid);
    // roster
    void addContact(const QString &jid);
    void renameContact(const QString &jid, const QString &name);
    void removeContact(const QString &jid);
    void acceptRequest(const QString &jid);
    void declineRequest(const QString &jid);
    // host services
    void openUrl(const QString &url);
    void copyText(const QString &text);
    void clearNotice();

signals:
    void stateChanged();
    void accountChanged();
    void noticeChanged();
    void omemoChanged();
    void requestsChanged();
    void certChanged();
    void settingsChanged();
    void busyChanged();
    /// A new message for a chat other than the open one (the UI may make a sound).
    void newMessage(const QString &jid);

private slots:
    void onNetworkOpened();
    void onNetworkError();
    void onClientState(int state);
    void onConnected();
    void onClosed(const QString &reason);
    void onMessageReceived(const XmppMessage &message);
    void onRosterReceived(const QList<RosterItem> &items);
    void onPresenceChanged(const RosterItem &item);
    void onSubscriptionRequested(const QString &jid);
    void onCertificateRejected(const QString &host, const QString &fingerprint, const QString &subject, const QString &errors);
    void onOmemoEnabled(bool enabled);
    void onOmemoSendFinished(const QString &id, bool ok, const QString &error);
    void onUploadFinished(bool ok, const QString &url, const QString &error);
    void onMediaReady(const QString &source, const QString &path);
    void onMediaFailed(const QString &source, const QString &error);
    void onReconnectTimer();

private:
    void setState(const QString &s);
    void setNotice(const QString &n);
    void setBusy(bool b);
    void loadAccount();
    void storeAccount();
    void connectSession();
    void scheduleReconnect();
    void startOmemo();
    void stopOmemo();
    QString dataDir() const;
    QString omemoDirFor(const QString &jid) const;
    void loadKnownChats();
    void storeMessage(const XmppMessage &m);
    void requestImagesFor(const XmppMessage &m);
    bool chatOmemo(const QString &jid) const;
    QString newMessageId() const;

    QSettings m_settings;
    NetworkManager *m_net;
    XmppClient *m_client;
    OmemoManager *m_omemo;
    MessageStore *m_store;
    MediaCache *m_media;
    ContactsModel *m_contacts;
    MessagesModel *m_chat;
    QNetworkConfigurationManager *m_netMgr;
    QNetworkSession *m_netSession;
    QTimer *m_reconnect;
    QDeclarativeView *m_view;
    XmppAccount m_account;
    QString m_state, m_notice, m_lastError;
    QStringList m_requests;
    bool m_wantOnline;
    bool m_certPrompt;
    QString m_certHost, m_certFingerprint, m_certSubject, m_certErrors;
    int m_reconnectDelay;
    QString m_uploadService;
    QHash<QString, RosterItem> m_pendingPresence;
    bool m_busy;
    bool m_started;
};

#endif
