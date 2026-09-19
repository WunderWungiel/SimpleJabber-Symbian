// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "omemomanager.h"
#include "../signal/session.h"
#include "../crypto/aes.h"

#include <QDateTime>
#include <QRegExp>
#include <QDebug>

using namespace Signal;

namespace {
const int PRE_KEY_COUNT = 100;
const int PRE_KEY_MIN = 20;
const quint32 SIGNED_PRE_KEY_ID = 1;
const int AES_KEY_SIZE = 16;
const int AES_IV_SIZE = 12;
const int GCM_TAG_SIZE = 16;
const int MEDIA_KEY_SIZE = 32;

QString ns(const char *s) { return QLatin1String(s); }

// Collects every <item> element below a container (PEP items live under pubsub/items or a
// pubsub#event/items), without recursing into an item's own children.
void collectItems(const XmlElement &el, QList<XmlElement> &out)
{
    const QList<XmlElement> &kids = el.children();
    for (int i = 0; i < kids.size(); ++i) {
        if (kids.at(i).name() == QLatin1String("item")) out.append(kids.at(i));
        else collectItems(kids.at(i), out);
    }
}

// The PEP item to read. ejabberd (xabber.org) keeps a node's item history, so a fetch can
// return several <item>s; the "current" one - or the newest when none is tagged - is the
// one that matters. Grabbing the first bundle/list in document order (as findDescendant
// would) can pick a stale item and miss a contact's current device, which is what makes a
// message come out "not encrypted for this device" on the other end.
XmlElement currentItem(const XmlElement &container)
{
    QList<XmlElement> items;
    collectItems(container, items);
    if (items.isEmpty()) return container;   // content passed directly, no <item> wrapper
    for (int i = 0; i < items.size(); ++i)
        if (items.at(i).attribute(QLatin1String("id")) == QLatin1String("current")) return items.at(i);
    return items.last();
}
}

// -- OmemoXml --------------------------------------------------------------------------

namespace OmemoXml {

QString bundleNode(quint32 deviceId)
{
    return QLatin1String(BUNDLE_NODE_PREFIX) + QString::number(deviceId);
}

XmlElement buildDeviceList(const QList<quint32> &ids)
{
    XmlElement list(ns(OMEMO_NS), QLatin1String("list"));
    for (int i = 0; i < ids.size(); ++i) {
        XmlElement d(ns(OMEMO_NS), QLatin1String("device"));
        d.setAttribute(QLatin1String("id"), QString::number(ids.at(i)));
        list.addChild(d);
    }
    return list;
}

QList<quint32> parseDeviceList(const XmlElement &container)
{
    QList<quint32> out;
    const XmlElement item = currentItem(container);
    const XmlElement list = item.is(ns(OMEMO_NS), QLatin1String("list")) ? item
                          : item.findDescendant(ns(OMEMO_NS), QLatin1String("list"));
    if (list.isNull()) return out;
    const QList<XmlElement> devices = list.childrenNamed(ns(OMEMO_NS), QLatin1String("device"));
    for (int i = 0; i < devices.size(); ++i) {
        bool ok = false;
        const quint32 id = devices.at(i).attribute(QLatin1String("id")).toUInt(&ok);
        if (ok && id != 0 && !out.contains(id)) out.append(id);
    }
    return out;
}

bool parseBundle(const XmlElement &container, quint32 deviceId, PreKeyBundle *out)
{
    const XmlElement bundle = currentItem(container).findDescendant(ns(OMEMO_NS), QLatin1String("bundle"));
    if (bundle.isNull()) return false;
    PreKeyBundle b;
    b.registrationId = deviceId;
    b.deviceId = deviceId;

    const XmlElement signed_ = bundle.child(ns(OMEMO_NS), QLatin1String("signedPreKeyPublic"));
    if (signed_.isNull()) return false;
    b.signedPreKeyPublic = Curve::decodePublic(QByteArray::fromBase64(signed_.text().trimmed().toLatin1()));
    b.signedPreKeyId = signed_.attribute(QLatin1String("signedPreKeyId")).toUInt();
    b.signedPreKeySignature = QByteArray::fromBase64(bundle.child(ns(OMEMO_NS), QLatin1String("signedPreKeySignature")).text().trimmed().toLatin1());
    b.identityKey = Curve::decodePublic(QByteArray::fromBase64(bundle.child(ns(OMEMO_NS), QLatin1String("identityKey")).text().trimmed().toLatin1()));
    if (b.signedPreKeyPublic.isEmpty() || b.identityKey.isEmpty() || b.signedPreKeySignature.size() != 64) return false;

    // One of the one-time pre keys, picked at random like the other clients do.
    const QList<XmlElement> preKeys = bundle.child(ns(OMEMO_NS), QLatin1String("prekeys")).childrenNamed(ns(OMEMO_NS), QLatin1String("preKeyPublic"));
    QList<XmlElement> usable;
    for (int i = 0; i < preKeys.size(); ++i)
        if (!preKeys.at(i).attribute(QLatin1String("preKeyId")).isEmpty()) usable.append(preKeys.at(i));
    if (usable.isEmpty()) return false;
    const XmlElement pick = usable.at(int(Curve::randomUInt() % quint32(usable.size())));
    b.preKeyId = pick.attribute(QLatin1String("preKeyId")).toUInt();
    b.preKeyPublic = Curve::decodePublic(QByteArray::fromBase64(pick.text().trimmed().toLatin1()));
    if (b.preKeyPublic.isEmpty()) return false;
    *out = b;
    return true;
}

} // namespace OmemoXml

// -- SendOp ----------------------------------------------------------------------------

struct OmemoManager::SendOp
{
    QString to, body, id;
    QByteArray keyAuthTag, iv, cipherText;
    QList<QPair<QString, quint32> > targets;
    int nextTarget;
    QList<XmlElement> keyNodes;
    SendOp() : nextTarget(0) {}
};

// -- OmemoManager ----------------------------------------------------------------------

OmemoManager::OmemoManager(XmppClient *client, const QString &ownBareJid, const QString &storeDir, QObject *parent)
    : QObject(parent), m_client(client), m_ownJid(ownBareJid.toLower()), m_store(storeDir),
      m_enabled(false), m_openAccessSupported(true)
{
}

QString OmemoManager::formatFingerprint(const QByteArray &raw)
{
    const QString hex = QString::fromLatin1(raw.toHex());
    QString out;
    for (int i = 0; i < hex.size(); i += 8) {
        if (!out.isEmpty()) out += QLatin1Char(' ');
        out += hex.mid(i, 8);
    }
    return out;
}

QString OmemoManager::ownFingerprint() const
{
    if (!m_store.identityKeyPair().isValid()) return QString();
    return formatFingerprint(m_store.identityKeyPair().publicKey);
}

QString OmemoManager::contactFingerprint(const QString &bareJid) const
{
    const QByteArray raw = m_store.loadIdentity(bareJid.toLower());
    return raw.size() == 32 ? formatFingerprint(raw) : QString();
}

// -- enable / publish --

void OmemoManager::enable()
{
    if (!m_store.loadOrCreateOwnDevice()) { emit enabledChanged(false); return; }
    ensureLocalKeyMaterial();
    // Hooked at once: an encrypted message arriving during the publishes must not be shown
    // as its "your client doesn't support OMEMO" fallback body.
    m_client->setMessageHook(this);
    IqCall *call = publish(OmemoXml::bundleNode(m_store.deviceId()), buildBundle());
    connect(call, SIGNAL(finished(IqCall*)), this, SLOT(onPublishBundleDone(IqCall*)));
}

void OmemoManager::disable()
{
    m_enabled = false;
    m_client->setMessageHook(0);
    m_deviceLists.clear();
    m_granted.clear();
}

void OmemoManager::ensureLocalKeyMaterial()
{
    if (!m_store.containsSignedPreKey(SIGNED_PRE_KEY_ID)) {
        SignedPreKeyRecord spk;
        spk.id = SIGNED_PRE_KEY_ID;
        spk.timestamp = quint64(QDateTime::currentDateTime().toMSecsSinceEpoch());
        spk.keyPair = Curve::generateKeyPair();
        spk.signature = Curve::sign(m_store.identityKeyPair().privateKey, Curve::encodePublic(spk.keyPair.publicKey));
        m_store.storeSignedPreKey(SIGNED_PRE_KEY_ID, spk);
    }
    if (m_store.preKeyIds().size() < PRE_KEY_MIN) refillPreKeys();
}

void OmemoManager::refillPreKeys()
{
    quint32 start = 1;
    const QList<quint32> existing = m_store.preKeyIds();
    for (int i = 0; i < existing.size(); ++i)
        if (existing.at(i) >= start) start = existing.at(i) + 1;
    for (int i = 0; i < PRE_KEY_COUNT; ++i) {
        PreKeyRecord pk;
        pk.id = ((start - 1 + quint32(i)) % 0xFFFFFE) + 1;   // ids wrap below Medium.MAX_VALUE
        pk.keyPair = Curve::generateKeyPair();
        m_store.storePreKey(pk.id, pk);
    }
}

XmlElement OmemoManager::buildBundle() const
{
    SignedPreKeyRecord spk;
    m_store.loadSignedPreKey(SIGNED_PRE_KEY_ID, &spk);

    XmlElement bundle(ns(OmemoXml::OMEMO_NS), QLatin1String("bundle"));
    XmlElement signed_(ns(OmemoXml::OMEMO_NS), QLatin1String("signedPreKeyPublic"),
                       QString::fromLatin1(Curve::encodePublic(spk.keyPair.publicKey).toBase64()));
    signed_.setAttribute(QLatin1String("signedPreKeyId"), QString::number(spk.id));
    bundle.addChild(signed_);
    bundle.addChild(XmlElement(ns(OmemoXml::OMEMO_NS), QLatin1String("signedPreKeySignature"), QString::fromLatin1(spk.signature.toBase64())));
    bundle.addChild(XmlElement(ns(OmemoXml::OMEMO_NS), QLatin1String("identityKey"),
                               QString::fromLatin1(Curve::encodePublic(m_store.identityKeyPair().publicKey).toBase64())));
    XmlElement preKeys(ns(OmemoXml::OMEMO_NS), QLatin1String("prekeys"));
    const QList<quint32> ids = m_store.preKeyIds();
    for (int i = 0; i < ids.size(); ++i) {
        PreKeyRecord pk;
        if (!m_store.loadPreKey(ids.at(i), &pk)) continue;
        XmlElement node(ns(OmemoXml::OMEMO_NS), QLatin1String("preKeyPublic"),
                        QString::fromLatin1(Curve::encodePublic(pk.keyPair.publicKey).toBase64()));
        node.setAttribute(QLatin1String("preKeyId"), QString::number(pk.id));
        preKeys.addChild(node);
    }
    bundle.addChild(preKeys);
    return bundle;
}

IqCall *OmemoManager::publish(const QString &node, const XmlElement &content)
{
    XmlElement item(ns(OmemoXml::PUBSUB_NS), QLatin1String("item"));
    item.setAttribute(QLatin1String("id"), QLatin1String(OmemoXml::ITEM_ID_CURRENT));
    item.addChild(content);
    XmlElement pub(ns(OmemoXml::PUBSUB_NS), QLatin1String("publish"));
    pub.setAttribute(QLatin1String("node"), node);
    pub.addChild(item);
    XmlElement pubsub(ns(OmemoXml::PUBSUB_NS), QLatin1String("pubsub"));
    pubsub.addChild(pub);

    if (m_openAccessSupported) {
        // XEP-0060 publish-options: open access, so contacts can read the node even on
        // servers whose default is a whitelist.
        XmlElement form(ns(OmemoXml::DATA_NS), QLatin1String("x"));
        form.setAttribute(QLatin1String("type"), QLatin1String("submit"));
        XmlElement formType(ns(OmemoXml::DATA_NS), QLatin1String("field"));
        formType.setAttribute(QLatin1String("var"), QLatin1String("FORM_TYPE"));
        formType.setAttribute(QLatin1String("type"), QLatin1String("hidden"));
        formType.addChild(XmlElement(ns(OmemoXml::DATA_NS), QLatin1String("value"), QLatin1String("http://jabber.org/protocol/pubsub#publish-options")));
        XmlElement access(ns(OmemoXml::DATA_NS), QLatin1String("field"));
        access.setAttribute(QLatin1String("var"), QLatin1String("pubsub#access_model"));
        access.addChild(XmlElement(ns(OmemoXml::DATA_NS), QLatin1String("value"), QLatin1String("open")));
        form.addChild(formType);
        form.addChild(access);
        XmlElement options(ns(OmemoXml::PUBSUB_NS), QLatin1String("publish-options"));
        options.addChild(form);
        pubsub.addChild(options);

        // Remember the plain form so a refusal can be retried without the options.
        XmlElement plain(ns(OmemoXml::PUBSUB_NS), QLatin1String("pubsub"));
        plain.addChild(pub);
        IqCall *call = m_client->request(QString(), QLatin1String("set"), pubsub);
        m_publishRetry.insert(call, plain);
        connect(call, SIGNAL(finished(IqCall*)), this, SLOT(onPublishRetryDone(IqCall*)));
        return call;
    }
    return m_client->request(QString(), QLatin1String("set"), pubsub);
}

void OmemoManager::onPublishRetryDone(IqCall *call)
{
    const XmlElement plain = m_publishRetry.take(call);
    if (!call->isError()) return;
    // The publish-options were refused. Usually the node already exists with a non-open
    // access model (created before, or by another client): reconfigure it to open via
    // pubsub#owner, then publish the plain item. That is what lets a contact who is not
    // subscribed - or Conversations - read our bundle and device list. Best-effort: if the
    // reconfigure also fails, publish anyway so at least subscribed contacts get it.
    const QString node = plain.findDescendant(ns(OmemoXml::PUBSUB_NS), QLatin1String("publish")).attribute(QLatin1String("node"));
    if (!node.isEmpty() && !m_reconfigured.contains(node)) {
        m_reconfigured.insert(node);
        IqCall *cfg = reconfigureNodeOpen(node);
        m_publishAfterConfig.insert(cfg, plain);
        connect(cfg, SIGNAL(finished(IqCall*)), this, SLOT(onReconfigureDone(IqCall*)));
        return;
    }
    m_client->request(QString(), QLatin1String("set"), plain);
}

IqCall *OmemoManager::reconfigureNodeOpen(const QString &node)
{
    // pubsub#owner configure with just FORM_TYPE + access_model=open; ejabberd keeps the
    // node's other settings and only changes what the form carries.
    XmlElement form(ns(OmemoXml::DATA_NS), QLatin1String("x"));
    form.setAttribute(QLatin1String("type"), QLatin1String("submit"));
    XmlElement formType(ns(OmemoXml::DATA_NS), QLatin1String("field"));
    formType.setAttribute(QLatin1String("var"), QLatin1String("FORM_TYPE"));
    formType.setAttribute(QLatin1String("type"), QLatin1String("hidden"));
    formType.addChild(XmlElement(ns(OmemoXml::DATA_NS), QLatin1String("value"), QLatin1String("http://jabber.org/protocol/pubsub#node_config")));
    XmlElement access(ns(OmemoXml::DATA_NS), QLatin1String("field"));
    access.setAttribute(QLatin1String("var"), QLatin1String("pubsub#access_model"));
    access.addChild(XmlElement(ns(OmemoXml::DATA_NS), QLatin1String("value"), QLatin1String("open")));
    form.addChild(formType);
    form.addChild(access);
    XmlElement configure(ns(OmemoXml::PUBSUB_OWNER_NS), QLatin1String("configure"));
    configure.setAttribute(QLatin1String("node"), node);
    configure.addChild(form);
    XmlElement pubsub(ns(OmemoXml::PUBSUB_OWNER_NS), QLatin1String("pubsub"));
    pubsub.addChild(configure);
    return m_client->request(QString(), QLatin1String("set"), pubsub);
}

void OmemoManager::onReconfigureDone(IqCall *call)
{
    const XmlElement plain = m_publishAfterConfig.take(call);
    if (plain.isNull()) return;
    // Whether or not the reconfigure succeeded, publish the item now.
    m_client->request(QString(), QLatin1String("set"), plain);
}

void OmemoManager::onPublishBundleDone(IqCall *call)
{
    Q_UNUSED(call);
    IqCall *fetch = retrieveItems(m_ownJid, QLatin1String(OmemoXml::DEVICE_LIST_NODE));
    connect(fetch, SIGNAL(finished(IqCall*)), this, SLOT(onOwnDeviceListFetched(IqCall*)));
}

void OmemoManager::onOwnDeviceListFetched(IqCall *call)
{
    QList<quint32> devices = call->isResult() ? OmemoXml::parseDeviceList(call->reply()) : QList<quint32>();
    if (!devices.contains(m_store.deviceId())) {
        devices.append(m_store.deviceId());
        m_ownDevicesPending = devices;
        IqCall *pub = publish(QLatin1String(OmemoXml::DEVICE_LIST_NODE), OmemoXml::buildDeviceList(devices));
        connect(pub, SIGNAL(finished(IqCall*)), this, SLOT(onOwnDeviceListPublished(IqCall*)));
        return;
    }
    m_deviceLists.insert(m_ownJid, devices);
    m_enabled = true;
    emit enabledChanged(true);
}

void OmemoManager::onOwnDeviceListPublished(IqCall *call)
{
    Q_UNUSED(call);
    m_deviceLists.insert(m_ownJid, m_ownDevicesPending);
    m_enabled = true;
    emit enabledChanged(true);
}

void OmemoManager::republishBundle()
{
    if (m_store.preKeyIds().size() < PRE_KEY_MIN) refillPreKeys();
    publish(OmemoXml::bundleNode(m_store.deviceId()), buildBundle());
}

IqCall *OmemoManager::retrieveItems(const QString &bareJid, const QString &node)
{
    XmlElement items(ns(OmemoXml::PUBSUB_NS), QLatin1String("items"));
    items.setAttribute(QLatin1String("node"), node);
    // Only the newest item: a node that kept history must not hand us a stale bundle or
    // device list (see currentItem). currentItem still guards the reply in case the server
    // ignores this.
    items.setAttribute(QLatin1String("max_items"), QLatin1String("1"));
    XmlElement pubsub(ns(OmemoXml::PUBSUB_NS), QLatin1String("pubsub"));
    pubsub.addChild(items);
    return m_client->request(bareJid, QLatin1String("get"), pubsub);
}

void OmemoManager::grantNodeAccess(const QString &contact)
{
    // Servers that force a whitelist (ejabberd) refuse contacts our bundle otherwise.
    if (contact.isEmpty() || contact == m_ownJid || m_granted.contains(contact)) return;
    m_granted.insert(contact);
    const QString nodes[2] = { QLatin1String(OmemoXml::DEVICE_LIST_NODE), OmemoXml::bundleNode(m_store.deviceId()) };
    for (int i = 0; i < 2; ++i) {
        XmlElement aff(ns(OmemoXml::PUBSUB_OWNER_NS), QLatin1String("affiliation"));
        aff.setAttribute(QLatin1String("jid"), contact);
        aff.setAttribute(QLatin1String("affiliation"), QLatin1String("member"));
        XmlElement affs(ns(OmemoXml::PUBSUB_OWNER_NS), QLatin1String("affiliations"));
        affs.setAttribute(QLatin1String("node"), nodes[i]);
        affs.addChild(aff);
        XmlElement pubsub(ns(OmemoXml::PUBSUB_OWNER_NS), QLatin1String("pubsub"));
        pubsub.addChild(affs);
        IqCall *call = m_client->request(QString(), QLatin1String("set"), pubsub);
        connect(call, SIGNAL(finished(IqCall*)), this, SLOT(onGrantDone(IqCall*)));
    }
}

void OmemoManager::onGrantDone(IqCall *) {}

// -- sending --

void OmemoManager::sendEncrypted(const QString &toBareIn, const QString &body, const QString &id)
{
    const QString toBare = toBareIn.toLower();
    if (!m_enabled || toBare.isEmpty()) { emit sendFinished(id, false, tr("OMEMO is not ready")); return; }
    grantNodeAccess(toBare);

    SendOp *op = new SendOp;
    op->to = toBare;
    op->body = body;
    op->id = id;
    const QByteArray key = Curve::randomBytes(AES_KEY_SIZE);
    op->iv = Curve::randomBytes(AES_IV_SIZE);
    QByteArray tag;
    if (!encryptGcm(body.toUtf8(), key, op->iv, &op->cipherText, &tag)) { delete op; emit sendFinished(id, false, tr("encryption failed")); return; }
    op->keyAuthTag = key + tag;

    IqCall *call = retrieveItems(toBare, QLatin1String(OmemoXml::DEVICE_LIST_NODE));
    m_sendCalls.insert(call, op);
    connect(call, SIGNAL(finished(IqCall*)), this, SLOT(onSendDeviceListFetched(IqCall*)));
}

QList<quint32> OmemoManager::mergeIntoCache(const QString &bareJid, const QList<quint32> &fetched)
{
    QList<quint32> merged = m_deviceLists.value(bareJid);
    for (int i = 0; i < fetched.size(); ++i)
        if (!merged.contains(fetched.at(i))) merged.append(fetched.at(i));
    m_deviceLists.insert(bareJid, merged);
    return merged;
}

void OmemoManager::onSendDeviceListFetched(IqCall *call)
{
    SendOp *op = m_sendCalls.take(call);
    if (!op) return;
    // The fresh list UNIONED with what we already know: on whitelist servers a contact's
    // device-list node is often unreadable, but a device learned from an incoming message
    // (or a session on disk) must still be encrypted for.
    QList<quint32> devices = mergeIntoCache(op->to, call->isResult() ? OmemoXml::parseDeviceList(call->reply()) : QList<quint32>());
    const QList<quint32> onDisk = m_store.subDeviceSessions(op->to);
    for (int i = 0; i < onDisk.size(); ++i)
        if (!devices.contains(onDisk.at(i))) devices.append(onDisk.at(i));
    for (int i = 0; i < devices.size(); ++i) {
        if (op->to == m_ownJid && devices.at(i) == m_store.deviceId()) continue;   // never for ourselves
        op->targets.append(qMakePair(op->to, devices.at(i)));
    }

    if (op->to != m_ownJid) {
        if (!m_deviceLists.contains(m_ownJid)) {
            IqCall *own = retrieveItems(m_ownJid, QLatin1String(OmemoXml::DEVICE_LIST_NODE));
            m_sendCalls.insert(own, op);
            connect(own, SIGNAL(finished(IqCall*)), this, SLOT(onSendOwnDeviceListFetched(IqCall*)));
            return;
        }
        const QList<quint32> own = m_deviceLists.value(m_ownJid);
        for (int i = 0; i < own.size(); ++i)
            if (own.at(i) != m_store.deviceId()) op->targets.append(qMakePair(m_ownJid, own.at(i)));
    }
    continueSend(op);
}

void OmemoManager::onSendOwnDeviceListFetched(IqCall *call)
{
    SendOp *op = m_sendCalls.take(call);
    if (!op) return;
    const QList<quint32> own = call->isResult() ? OmemoXml::parseDeviceList(call->reply()) : QList<quint32>();
    m_deviceLists.insert(m_ownJid, own);
    for (int i = 0; i < own.size(); ++i)
        if (own.at(i) != m_store.deviceId()) op->targets.append(qMakePair(m_ownJid, own.at(i)));
    continueSend(op);
}

void OmemoManager::continueSend(SendOp *op)
{
    while (op->nextTarget < op->targets.size()) {
        const QPair<QString, quint32> &t = op->targets.at(op->nextTarget);
        const Address addr(t.first, t.second);
        if (!m_store.containsSession(addr)) {
            IqCall *call = retrieveItems(t.first, OmemoXml::bundleNode(t.second));
            m_sendCalls.insert(call, op);
            connect(call, SIGNAL(finished(IqCall*)), this, SLOT(onBundleFetched(IqCall*)));
            return;   // resumes in onBundleFetched
        }
        SessionCipher cipher(&m_store, addr);
        QByteArray wire;
        bool preKey = false;
        QString err;
        if (cipher.encrypt(op->keyAuthTag, &wire, &preKey, &err)) {
            XmlElement key(ns(OmemoXml::OMEMO_NS), QLatin1String("key"), QString::fromLatin1(wire.toBase64()));
            key.setAttribute(QLatin1String("rid"), QString::number(t.second));
            if (preKey) key.setAttribute(QLatin1String("prekey"), QLatin1String("true"));
            op->keyNodes.append(key);
        } else {
            qWarning() << "OMEMO: encrypt for" << addr.toString() << "failed:" << err;
        }
        ++op->nextTarget;
    }

    qWarning() << "OMEMO: send to" << op->to << "- encrypted for" << op->keyNodes.size() << "of" << op->targets.size() << "known devices";
    if (op->keyNodes.isEmpty()) { finishSend(op, false, tr("this contact has no reachable OMEMO device")); return; }

    XmlElement header(ns(OmemoXml::OMEMO_NS), QLatin1String("header"));
    header.setAttribute(QLatin1String("sid"), QString::number(m_store.deviceId()));
    for (int i = 0; i < op->keyNodes.size(); ++i) header.addChild(op->keyNodes.at(i));
    header.addChild(XmlElement(ns(OmemoXml::OMEMO_NS), QLatin1String("iv"), QString::fromLatin1(op->iv.toBase64())));
    XmlElement encrypted(ns(OmemoXml::OMEMO_NS), QLatin1String("encrypted"));
    encrypted.addChild(header);
    encrypted.addChild(XmlElement(ns(OmemoXml::OMEMO_NS), QLatin1String("payload"), QString::fromLatin1(op->cipherText.toBase64())));

    XmlElement message(ns(Xmpp::CLIENT_NS), QLatin1String("message"));
    message.setAttribute(QLatin1String("to"), op->to);
    message.setAttribute(QLatin1String("type"), QLatin1String("chat"));
    message.setAttribute(QLatin1String("id"), op->id);
    message.addChild(encrypted);
    // XEP-0380 so other clients label it, a fallback body for clients without OMEMO, and
    // XEP-0334 so the server stores it for offline delivery.
    XmlElement eme(ns(OmemoXml::EME_NS), QLatin1String("encryption"));
    eme.setAttribute(QLatin1String("namespace"), ns(OmemoXml::OMEMO_NS));
    eme.setAttribute(QLatin1String("name"), QLatin1String("OMEMO"));
    message.addChild(eme);
    message.addChild(XmlElement(ns(Xmpp::CLIENT_NS), QLatin1String("body"),
                                QLatin1String("I sent you an OMEMO encrypted message but your client doesn't support it.")));
    message.addChild(XmlElement(ns(OmemoXml::HINTS_NS), QLatin1String("store")));
    m_client->sendStanza(message);
    finishSend(op, true, QString());
}

void OmemoManager::onBundleFetched(IqCall *call)
{
    SendOp *op = m_sendCalls.take(call);
    if (!op) return;
    if (op->nextTarget < op->targets.size()) {
        const QPair<QString, quint32> &t = op->targets.at(op->nextTarget);
        PreKeyBundle bundle;
        // A device whose bundle we cannot fetch (offline, dead, or a node we may not read)
        // is simply skipped - counted in the send summary rather than warned per device.
        if (call->isResult() && OmemoXml::parseBundle(call->reply(), t.second, &bundle)) {
            SessionBuilder builder(&m_store, Address(t.first, t.second));
            QString err;
            if (!builder.processPreKeyBundle(bundle, &err)) qWarning() << "OMEMO: bundle of" << t.first << t.second << "rejected:" << err;
        }
        if (!m_store.containsSession(Address(t.first, t.second))) ++op->nextTarget;   // skip it
    }
    continueSend(op);
}

void OmemoManager::finishSend(SendOp *op, bool ok, const QString &error)
{
    const QString id = op->id;
    delete op;
    emit sendFinished(id, ok, error);
}

// -- receiving --

bool OmemoManager::handleIncomingMessage(const XmlElement &message)
{
    const XmlElement evt = message.child(ns(OmemoXml::PUBSUB_EVENT_NS), QLatin1String("event"));
    if (!evt.isNull() && handleDeviceListEvent(message, evt)) return true;

    const XmlElement encrypted = message.child(ns(OmemoXml::OMEMO_NS), QLatin1String("encrypted"));
    if (encrypted.isNull()) return false;

    QString fromBare = Jid::bareOf(message.attribute(QLatin1String("from")));
    if (fromBare.isEmpty()) fromBare = m_ownJid;
    QString plaintext;
    if (decryptMessage(encrypted, fromBare, &plaintext)) {
        XmppMessage m(fromBare, plaintext, false);
        m.id = message.attribute(QLatin1String("id"));
        m.encrypted = true;
        m_client->deliverMessage(m);
    }
    return true;   // consumed either way: a message we cannot read is dropped, not shown as garbage
}

bool OmemoManager::handleDeviceListEvent(const XmlElement &message, const XmlElement &evt)
{
    const XmlElement items = evt.child(ns(OmemoXml::PUBSUB_EVENT_NS), QLatin1String("items"));
    if (items.isNull() || items.attribute(QLatin1String("node")) != QLatin1String(OmemoXml::DEVICE_LIST_NODE)) return false;
    QString fromBare = Jid::bareOf(message.attribute(QLatin1String("from")));
    if (fromBare.isEmpty()) fromBare = m_ownJid;
    QList<quint32> devices = OmemoXml::parseDeviceList(evt);
    m_deviceLists.insert(fromBare, devices);
    if (fromBare == m_ownJid && m_enabled && !devices.contains(m_store.deviceId())) {
        // Another client of ours published a list without us: put ourselves back.
        devices.append(m_store.deviceId());
        m_deviceLists.insert(m_ownJid, devices);
        publish(QLatin1String(OmemoXml::DEVICE_LIST_NODE), OmemoXml::buildDeviceList(devices));
    }
    return true;
}

bool OmemoManager::decryptMessage(const XmlElement &encrypted, const QString &fromBare, QString *plaintext)
{
    const XmlElement header = encrypted.child(ns(OmemoXml::OMEMO_NS), QLatin1String("header"));
    if (header.isNull()) return false;
    bool ok = false;
    const quint32 sid = header.attribute(QLatin1String("sid")).toUInt(&ok);
    if (!ok) return false;

    XmlElement ourKey;
    bool isPreKey = false;
    const QList<XmlElement> keys = header.childrenNamed(ns(OmemoXml::OMEMO_NS), QLatin1String("key"));
    for (int i = 0; i < keys.size(); ++i) {
        if (keys.at(i).attribute(QLatin1String("rid")).toUInt() == m_store.deviceId()) {
            ourKey = keys.at(i);
            const QString pk = keys.at(i).attribute(QLatin1String("prekey"));
            isPreKey = pk == QLatin1String("true") || pk == QLatin1String("1");
            break;
        }
    }
    if (ourKey.isNull()) return false;   // not addressed to this device

    const Address address(fromBare, sid);
    SessionCipher cipher(&m_store, address);
    const QByteArray wire = QByteArray::fromBase64(ourKey.text().trimmed().toLatin1());
    QByteArray keyAuthTag;
    QString err;
    if (isPreKey) {
        const PreKeySignalMessage pre = PreKeySignalMessage::parse(wire);
        if (!pre.isValid() || !cipher.decryptPreKeyMessage(pre, &keyAuthTag, &err)) { qWarning() << "OMEMO: prekey decrypt failed:" << err; return false; }
        republishBundle();   // the contact used one of our one-time pre keys
    } else {
        const SignalMessage msg = SignalMessage::parse(wire);
        if (!msg.isValid() || !cipher.decryptMessage(msg, &keyAuthTag, &err)) { qWarning() << "OMEMO: decrypt failed:" << err; return false; }
    }
    if (keyAuthTag.size() < AES_KEY_SIZE) return false;

    // We could read from this device: remember it so replies encrypt for it even when the
    // contact's device-list node is unreadable.
    rememberDevice(fromBare, sid);
    noteOwnDeviceSeen(fromBare, sid);

    const XmlElement payload = encrypted.child(ns(OmemoXml::OMEMO_NS), QLatin1String("payload"));
    if (payload.isNull() || payload.text().trimmed().isEmpty()) return false;   // key transport only

    const QByteArray aesKey = keyAuthTag.left(AES_KEY_SIZE);
    const QByteArray authTag = keyAuthTag.mid(AES_KEY_SIZE);
    const QByteArray iv = QByteArray::fromBase64(header.child(ns(OmemoXml::OMEMO_NS), QLatin1String("iv")).text().trimmed().toLatin1());
    const QByteArray cipherText = QByteArray::fromBase64(payload.text().trimmed().toLatin1());
    QByteArray plain;
    if (!decryptGcm(cipherText, authTag, aesKey, iv, &plain)) { qWarning() << "OMEMO: payload GCM tag mismatch"; return false; }
    *plaintext = QString::fromUtf8(plain.constData(), plain.size());
    return true;
}

void OmemoManager::rememberDevice(const QString &bareJid, quint32 deviceId)
{
    QList<quint32> devices = m_deviceLists.value(bareJid);
    if (!devices.contains(deviceId)) { devices.append(deviceId); m_deviceLists.insert(bareJid, devices); }
}

void OmemoManager::noteOwnDeviceSeen(const QString &fromBare, quint32 deviceId)
{
    if (fromBare != m_ownJid || deviceId == m_store.deviceId()) return;
    QList<quint32> own = m_deviceLists.value(m_ownJid);
    if (own.contains(deviceId)) return;
    own.append(deviceId);
    if (!own.contains(m_store.deviceId())) own.append(m_store.deviceId());
    m_deviceLists.insert(m_ownJid, own);
    publish(QLatin1String(OmemoXml::DEVICE_LIST_NODE), OmemoXml::buildDeviceList(own));
}

// -- GCM helpers --

bool OmemoManager::encryptGcm(const QByteArray &plain, const QByteArray &key, const QByteArray &iv, QByteArray *cipher, QByteArray *tag)
{
    aes_gcm_ctx g;
    if (aes_gcm_set_key(&g, reinterpret_cast<const unsigned char *>(key.constData()), key.size()) != 0 || iv.size() != AES_IV_SIZE) return false;
    cipher->resize(plain.size());
    tag->resize(GCM_TAG_SIZE);
    aes_gcm_encrypt(&g, reinterpret_cast<const unsigned char *>(iv.constData()), 0, 0,
                    reinterpret_cast<const unsigned char *>(plain.constData()), plain.size(),
                    reinterpret_cast<unsigned char *>(cipher->data()), reinterpret_cast<unsigned char *>(tag->data()));
    return true;
}

bool OmemoManager::decryptGcm(const QByteArray &cipher, const QByteArray &tag, const QByteArray &key, const QByteArray &iv, QByteArray *plain)
{
    aes_gcm_ctx g;
    if (aes_gcm_set_key(&g, reinterpret_cast<const unsigned char *>(key.constData()), key.size()) != 0 || iv.size() != AES_IV_SIZE || tag.size() != GCM_TAG_SIZE) return false;
    plain->resize(cipher.size());
    return aes_gcm_decrypt(&g, reinterpret_cast<const unsigned char *>(iv.constData()), 0, 0,
                           reinterpret_cast<const unsigned char *>(cipher.constData()), cipher.size(),
                           reinterpret_cast<unsigned char *>(plain->data()), reinterpret_cast<const unsigned char *>(tag.constData())) == 0;
}

// -- media (aesgcm:// urls) --

bool OmemoManager::isAesGcmUrl(const QString &s)
{
    static const QRegExp re(QLatin1String("^aesgcm://\\S+#([0-9a-fA-F]{88}|[0-9a-fA-F]{96})$"));
    return re.exactMatch(s.trimmed());
}

bool OmemoManager::isAesGcmImageUrl(const QString &s)
{
    if (!isAesGcmUrl(s)) return false;
    const QString u = s.trimmed();
    const int hash = u.lastIndexOf(QLatin1Char('#'));
    const QString path = (hash >= 0 ? u.left(hash) : u).toLower();
    return path.endsWith(QLatin1String(".jpg")) || path.endsWith(QLatin1String(".jpeg")) || path.endsWith(QLatin1String(".png"))
        || path.endsWith(QLatin1String(".gif")) || path.endsWith(QLatin1String(".webp"));
}

bool OmemoManager::parseAesGcmUrl(const QString &urlIn, QString *downloadUrl, QByteArray *key, QByteArray *iv)
{
    if (!isAesGcmUrl(urlIn)) return false;
    const QString url = urlIn.trimmed();
    const int hash = url.lastIndexOf(QLatin1Char('#'));
    const QByteArray ivKey = QByteArray::fromHex(url.mid(hash + 1).toLatin1());
    const int ivLen = ivKey.size() - MEDIA_KEY_SIZE;
    if (ivLen <= 0) return false;
    *downloadUrl = QLatin1String("https://") + url.mid(9, hash - 9);
    *iv = ivKey.left(ivLen);
    *key = ivKey.mid(ivLen);
    return true;
}

QByteArray OmemoManager::encryptMedia(const QByteArray &plain, QByteArray *key, QByteArray *iv)
{
    *key = Curve::randomBytes(MEDIA_KEY_SIZE);
    *iv = Curve::randomBytes(AES_IV_SIZE);
    QByteArray cipher, tag;
    if (!encryptGcm(plain, *key, *iv, &cipher, &tag)) return QByteArray();
    return cipher + tag;
}

bool OmemoManager::decryptMedia(const QByteArray &cipherWithTag, const QByteArray &key, const QByteArray &iv, QByteArray *plain)
{
    if (cipherWithTag.size() < GCM_TAG_SIZE) return false;
    // Only 12-byte IVs are supported by the GCM here; older clients used 16 (deprecated).
    if (iv.size() != AES_IV_SIZE) return false;
    return decryptGcm(cipherWithTag.left(cipherWithTag.size() - GCM_TAG_SIZE), cipherWithTag.right(GCM_TAG_SIZE), key, iv, plain);
}

QString OmemoManager::buildAesGcmUrl(const QString &httpsUrl, const QByteArray &iv, const QByteArray &key)
{
    QString body = httpsUrl;
    if (body.startsWith(QLatin1String("https://"), Qt::CaseInsensitive)) body = body.mid(8);
    else if (body.startsWith(QLatin1String("http://"), Qt::CaseInsensitive)) body = body.mid(7);
    return QLatin1String("aesgcm://") + body + QLatin1Char('#') + QString::fromLatin1((iv + key).toHex());
}
