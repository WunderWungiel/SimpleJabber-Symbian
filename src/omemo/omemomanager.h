// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// OMEMO (XEP-0384, the eu.siacs.conversations.axolotl namespace every client still
// speaks) for one account: owns the Signal store, publishes the device list and bundle
// over PEP, fetches contacts' device lists and bundles to build sessions, and wraps /
// unwraps the <encrypted> envelope. Message payloads are AES-128-GCM; what the Signal
// session encrypts per device is key || tag (XEP-0384 v0.3).
//
// The XMPP client stays OMEMO-agnostic: this drives it through request() / sendStanza()
// and sees incoming <message> stanzas first as the MessageHook. Multi-step flows (enable,
// send) are small operation objects chained on IqCall::finished.
#ifndef SJ_OMEMOMANAGER_H
#define SJ_OMEMOMANAGER_H

#include "../xmpp/xmppclient.h"
#include "../signal/store.h"
#include "../signal/session.h"

#include <QHash>
#include <QList>
#include <QObject>
#include <QSet>
#include <QString>

namespace OmemoXml {
    const char *const OMEMO_NS = "eu.siacs.conversations.axolotl";
    const char *const EME_NS = "urn:xmpp:eme:0";
    const char *const HINTS_NS = "urn:xmpp:hints";
    const char *const PUBSUB_NS = "http://jabber.org/protocol/pubsub";
    const char *const PUBSUB_OWNER_NS = "http://jabber.org/protocol/pubsub#owner";
    const char *const PUBSUB_EVENT_NS = "http://jabber.org/protocol/pubsub#event";
    const char *const DATA_NS = "jabber:x:data";
    const char *const DEVICE_LIST_NODE = "eu.siacs.conversations.axolotl.devicelist";
    const char *const BUNDLE_NODE_PREFIX = "eu.siacs.conversations.axolotl.bundles:";
    const char *const ITEM_ID_CURRENT = "current";

    QString bundleNode(quint32 deviceId);
    XmlElement buildDeviceList(const QList<quint32> &ids);
    QList<quint32> parseDeviceList(const XmlElement &container);
    bool parseBundle(const XmlElement &container, quint32 deviceId, Signal::PreKeyBundle *out);
}

class OmemoManager : public QObject, public MessageHook
{
    Q_OBJECT
public:
    OmemoManager(XmppClient *client, const QString &ownBareJid, const QString &storeDir, QObject *parent = 0);

    bool isEnabled() const { return m_enabled; }
    quint32 ownDeviceId() const { return m_store.deviceId(); }
    /// Grouped lowercase hex of the raw 32-byte identity key, as Conversations shows it.
    QString ownFingerprint() const;
    /// The identity a contact presented (last seen), formatted; empty when none.
    QString contactFingerprint(const QString &bareJid) const;
    static QString formatFingerprint(const QByteArray &rawIdentityKey);

    /// Brings OMEMO up for this session (identity on first use, publish bundle and device
    /// list, hook incoming stanzas). enabledChanged(bool) reports the outcome.
    void enable();
    void disable();

    /// Encrypts body for every device of toBare (and our own other devices) and sends it.
    /// sendFinished(id, ok, error) follows; ok is false when no device could be reached.
    void sendEncrypted(const QString &toBare, const QString &body, const QString &id);

    // MessageHook
    bool handleIncomingMessage(const XmlElement &message);

    // -- AES-GCM media helpers (aesgcm:// urls, XEP-0454 style) --
    static bool isAesGcmUrl(const QString &s);
    static bool isAesGcmImageUrl(const QString &s);
    static bool parseAesGcmUrl(const QString &url, QString *downloadUrl, QByteArray *key, QByteArray *iv);
    static QByteArray encryptMedia(const QByteArray &plain, QByteArray *key, QByteArray *iv);
    static bool decryptMedia(const QByteArray &cipherWithTag, const QByteArray &key, const QByteArray &iv, QByteArray *plain);
    static QString buildAesGcmUrl(const QString &httpsUrl, const QByteArray &iv, const QByteArray &key);

    // -- AES-128-GCM message payload --
    static bool encryptGcm(const QByteArray &plain, const QByteArray &key, const QByteArray &iv, QByteArray *cipher, QByteArray *tag);
    static bool decryptGcm(const QByteArray &cipher, const QByteArray &tag, const QByteArray &key, const QByteArray &iv, QByteArray *plain);

signals:
    void enabledChanged(bool enabled);
    void sendFinished(const QString &id, bool ok, const QString &error);

private slots:
    void onPublishBundleDone(IqCall *call);
    void onOwnDeviceListFetched(IqCall *call);
    void onOwnDeviceListPublished(IqCall *call);
    void onSendDeviceListFetched(IqCall *call);
    void onSendOwnDeviceListFetched(IqCall *call);
    void onBundleFetched(IqCall *call);
    void onGrantDone(IqCall *call);
    void onPublishRetryDone(IqCall *call);
    void onReconfigureDone(IqCall *call);

private:
    friend class SendOp;
    struct SendOp;

    void ensureLocalKeyMaterial();
    void refillPreKeys();
    XmlElement buildBundle() const;
    IqCall *publish(const QString &node, const XmlElement &content);
    IqCall *retrieveItems(const QString &bareJid, const QString &node);
    void grantNodeAccess(const QString &contactBareJid);
    IqCall *reconfigureNodeOpen(const QString &node);
    void republishBundle();
    bool handleDeviceListEvent(const XmlElement &message, const XmlElement &evt);
    bool decryptMessage(const XmlElement &encrypted, const QString &fromBare, QString *plaintext);
    void rememberDevice(const QString &bareJid, quint32 deviceId);
    void noteOwnDeviceSeen(const QString &fromBare, quint32 deviceId);
    QList<quint32> mergeIntoCache(const QString &bareJid, const QList<quint32> &fetched);
    void continueSend(SendOp *op);
    void finishSend(SendOp *op, bool ok, const QString &error);

    XmppClient *m_client;
    QString m_ownJid;
    Signal::FileStore m_store;
    bool m_enabled;
    bool m_openAccessSupported;
    QHash<QString, QList<quint32> > m_deviceLists;
    QSet<QString> m_granted;
    QHash<IqCall *, SendOp *> m_sendCalls;
    QHash<IqCall *, XmlElement> m_publishRetry;
    QHash<IqCall *, XmlElement> m_publishAfterConfig;
    QSet<QString> m_reconfigured;
    QList<quint32> m_ownDevicesPending;
};

#endif
