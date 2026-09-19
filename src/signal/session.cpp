// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "session.h"
#include "../crypto/aes.h"

namespace Signal {

namespace {

const quint32 MAX_FUTURE_MESSAGES = 2000;

void fail(QString *error, const char *why)
{
    if (error) *error = QString::fromLatin1(why);
}

QByteArray discontinuityBytes()
{
    return QByteArray(32, char(0xFF));
}

/// HKDF("WhisperText") over the X3DH master secret -> root key || chain key.
void deriveInitialKeys(const QByteArray &masterSecret, RootKey *root, ChainKey *chain)
{
    const QByteArray derived = Kdf::deriveSecrets(masterSecret, QByteArray("WhisperText"), 64);
    *root = RootKey(derived.mid(0, 32));
    *chain = ChainKey(derived.mid(32, 32), 0);
}

/// Alice's side of X3DH (RatchetingSession.initializeSession with AliceSignalProtocolParameters).
void initializeAliceSession(SessionState &state, const IdentityKeyPair &ourIdentity, const ECKeyPair &ourBaseKey,
                            const QByteArray &theirIdentity, const QByteArray &theirSignedPreKey,
                            const QByteArray &theirOneTimePreKey, const QByteArray &theirRatchetKey)
{
    state.setSessionVersion(CURRENT_VERSION);
    state.setRemoteIdentityKey(theirIdentity);
    state.setLocalIdentityKey(ourIdentity.publicKey);

    const ECKeyPair sendingRatchetKey = Curve::generateKeyPair();

    QByteArray secrets = discontinuityBytes();
    secrets += Curve::agreement(theirSignedPreKey, ourIdentity.privateKey);
    secrets += Curve::agreement(theirIdentity, ourBaseKey.privateKey);
    secrets += Curve::agreement(theirSignedPreKey, ourBaseKey.privateKey);
    if (!theirOneTimePreKey.isEmpty())
        secrets += Curve::agreement(theirOneTimePreKey, ourBaseKey.privateKey);

    RootKey root;
    ChainKey chain;
    deriveInitialKeys(secrets, &root, &chain);

    RootKey sendingRoot;
    ChainKey sendingChain;
    root.createChain(theirRatchetKey, sendingRatchetKey, &sendingRoot, &sendingChain);

    state.addReceiverChain(theirRatchetKey, chain);
    state.setSenderChain(sendingRatchetKey, sendingChain);
    state.setRootKey(sendingRoot);
}

/// Bob's side (BobSignalProtocolParameters).
void initializeBobSession(SessionState &state, const IdentityKeyPair &ourIdentity, const ECKeyPair &ourSignedPreKey,
                          const ECKeyPair &ourOneTimePreKey, bool hasOneTimePreKey, const ECKeyPair &ourRatchetKey,
                          const QByteArray &theirIdentity, const QByteArray &theirBaseKey)
{
    state.setSessionVersion(CURRENT_VERSION);
    state.setRemoteIdentityKey(theirIdentity);
    state.setLocalIdentityKey(ourIdentity.publicKey);

    QByteArray secrets = discontinuityBytes();
    secrets += Curve::agreement(theirIdentity, ourSignedPreKey.privateKey);
    secrets += Curve::agreement(theirBaseKey, ourIdentity.privateKey);
    secrets += Curve::agreement(theirBaseKey, ourSignedPreKey.privateKey);
    if (hasOneTimePreKey)
        secrets += Curve::agreement(theirBaseKey, ourOneTimePreKey.privateKey);

    RootKey root;
    ChainKey chain;
    deriveInitialKeys(secrets, &root, &chain);

    state.setSenderChain(ourRatchetKey, chain);
    state.setRootKey(root);
}

} // namespace

// -- symmetric helpers ---------------------------------------------------------------------

QByteArray aesCbcEncrypt(const QByteArray &key, const QByteArray &iv, const QByteArray &plaintext)
{
    aes_ctx ctx;
    if (aes_set_key(&ctx, reinterpret_cast<const unsigned char *>(key.constData()), key.size()) != 0 || iv.size() != 16)
        return QByteArray();
    QByteArray out(plaintext.size() + 16, 0);
    const unsigned long n = aes_cbc_pkcs7_encrypt(&ctx, reinterpret_cast<const unsigned char *>(iv.constData()),
                                                  reinterpret_cast<const unsigned char *>(plaintext.constData()), plaintext.size(),
                                                  reinterpret_cast<unsigned char *>(out.data()));
    out.resize(int(n));
    return out;
}

bool aesCbcDecrypt(const QByteArray &key, const QByteArray &iv, const QByteArray &ciphertext, QByteArray *plaintext)
{
    aes_ctx ctx;
    if (aes_set_key(&ctx, reinterpret_cast<const unsigned char *>(key.constData()), key.size()) != 0 || iv.size() != 16)
        return false;
    QByteArray out(ciphertext.size(), 0);
    const long n = aes_cbc_pkcs7_decrypt(&ctx, reinterpret_cast<const unsigned char *>(iv.constData()),
                                         reinterpret_cast<const unsigned char *>(ciphertext.constData()), ciphertext.size(),
                                         reinterpret_cast<unsigned char *>(out.data()));
    if (n < 0) return false;
    out.resize(int(n));
    *plaintext = out;
    return true;
}

// -- SessionBuilder --------------------------------------------------------------------------

bool SessionBuilder::processPreKeyBundle(const PreKeyBundle &bundle, QString *error)
{
    if (!m_store->isTrustedIdentity(m_remote.name, bundle.identityKey)) { fail(error, "untrusted identity"); return false; }
    if (bundle.signedPreKeyPublic.isEmpty()) { fail(error, "no signed pre key"); return false; }
    if (!Curve::verify(bundle.identityKey, Curve::encodePublic(bundle.signedPreKeyPublic), bundle.signedPreKeySignature)) {
        fail(error, "invalid signature on device key");
        return false;
    }

    SessionRecord record = m_store->loadSession(m_remote);
    const ECKeyPair ourBaseKey = Curve::generateKeyPair();
    const bool hasOneTime = !bundle.preKeyPublic.isEmpty();

    if (!record.isFresh()) record.archiveCurrentState();
    SessionState &state = record.sessionState();
    initializeAliceSession(state, m_store->identityKeyPair(), ourBaseKey, bundle.identityKey,
                           bundle.signedPreKeyPublic, hasOneTime ? bundle.preKeyPublic : QByteArray(),
                           bundle.signedPreKeyPublic);
    state.setUnacknowledgedPreKeyMessage(hasOneTime, bundle.preKeyId, bundle.signedPreKeyId, ourBaseKey.publicKey);
    state.setLocalRegistrationId(m_store->localRegistrationId());
    state.setRemoteRegistrationId(bundle.registrationId);
    state.setAliceBaseKey(ourBaseKey.publicKey);

    m_store->storeSession(m_remote, record);
    m_store->saveIdentity(m_remote.name, bundle.identityKey);
    return true;
}

bool SessionBuilder::processPreKeyMessage(SessionRecord &record, const PreKeySignalMessage &message,
                                          bool *hasConsumedPreKey, quint32 *consumedPreKeyId, QString *error)
{
    *hasConsumedPreKey = false;
    if (!m_store->isTrustedIdentity(m_remote.name, message.identityKey())) { fail(error, "untrusted identity"); return false; }

    // Already set up from this exact pre key message (a retransmission)? Then the inner
    // message simply decrypts with the existing state.
    if (record.hasSessionState(message.version(), message.baseKey())) return true;

    SignedPreKeyRecord signedPreKey;
    if (!m_store->loadSignedPreKey(message.signedPreKeyId(), &signedPreKey)) { fail(error, "unknown signed pre key id"); return false; }

    PreKeyRecord oneTime;
    bool hasOneTime = false;
    if (message.hasPreKeyId()) {
        if (!m_store->loadPreKey(message.preKeyId(), &oneTime)) { fail(error, "unknown pre key id"); return false; }
        hasOneTime = true;
    }

    if (!record.isFresh()) record.archiveCurrentState();
    SessionState &state = record.sessionState();
    initializeBobSession(state, m_store->identityKeyPair(), signedPreKey.keyPair, oneTime.keyPair, hasOneTime,
                         signedPreKey.keyPair, message.identityKey(), message.baseKey());
    state.setLocalRegistrationId(m_store->localRegistrationId());
    state.setRemoteRegistrationId(message.registrationId());
    state.setAliceBaseKey(message.baseKey());
    m_store->saveIdentity(m_remote.name, message.identityKey());

    if (hasOneTime && message.preKeyId() != 0xFFFFFF) {
        *hasConsumedPreKey = true;
        *consumedPreKeyId = message.preKeyId();
    }
    return true;
}

// -- SessionCipher ---------------------------------------------------------------------------

bool SessionCipher::encrypt(const QByteArray &plaintext, QByteArray *serialized, bool *isPreKeyMessage, QString *error)
{
    SessionRecord record = m_store->loadSession(m_remote);
    SessionState &state = record.sessionState();
    if (record.isFresh() || !state.hasSenderChain()) { fail(error, "no session"); return false; }

    const ChainKey chainKey = state.senderChainKey();
    const MessageKeys keys = chainKey.messageKeys();
    const QByteArray body = aesCbcEncrypt(keys.cipherKey, keys.iv, plaintext);
    if (body.isEmpty()) { fail(error, "encryption failed"); return false; }

    const SignalMessage message = SignalMessage::create(state.sessionVersion(), keys.macKey, state.senderRatchetKey(),
                                                        chainKey.index, state.previousCounter(), body,
                                                        state.localIdentityKey(), state.remoteIdentityKey());
    if (state.hasUnacknowledgedPreKeyMessage()) {
        const PreKeySignalMessage pre = PreKeySignalMessage::create(state.sessionVersion(), state.localRegistrationId(),
                                                                    state.pendingHasPreKeyId(), state.pendingPreKeyId(),
                                                                    state.pendingSignedPreKeyId(), state.pendingBaseKey(),
                                                                    state.localIdentityKey(), message);
        *serialized = pre.serialized();
        *isPreKeyMessage = true;
    } else {
        *serialized = message.serialized();
        *isPreKeyMessage = false;
    }

    state.setSenderChainKey(chainKey.next());
    m_store->storeSession(m_remote, record);
    return true;
}

bool SessionCipher::decryptPreKeyMessage(const PreKeySignalMessage &message, QByteArray *plaintext, QString *error)
{
    SessionRecord record = m_store->loadSession(m_remote);
    SessionBuilder builder(m_store, m_remote);
    bool consumed = false;
    quint32 consumedId = 0;
    if (!builder.processPreKeyMessage(record, message, &consumed, &consumedId, error)) return false;
    if (!decryptWithRecord(record, message.message(), plaintext, error)) return false;
    m_store->storeSession(m_remote, record);
    if (consumed) m_store->removePreKey(consumedId);
    return true;
}

bool SessionCipher::decryptMessage(const SignalMessage &message, QByteArray *plaintext, QString *error)
{
    if (!m_store->containsSession(m_remote)) { fail(error, "no session"); return false; }
    SessionRecord record = m_store->loadSession(m_remote);
    if (!decryptWithRecord(record, message, plaintext, error)) return false;
    m_store->storeSession(m_remote, record);
    return true;
}

bool SessionCipher::decryptWithRecord(SessionRecord &record, const SignalMessage &message, QByteArray *plaintext, QString *error)
{
    // The current state first, then each archived one: a message may belong to a session
    // that was since replaced (both sides started one at the same time).
    SessionState current = record.sessionState();
    QString firstError;
    if (decryptWithState(current, message, plaintext, &firstError)) {
        record.setState(current);
        return true;
    }
    QList<SessionState> &previous = record.previousStates();
    for (int i = 0; i < previous.size(); ++i) {
        SessionState promoted = previous.at(i);
        QString err;
        if (decryptWithState(promoted, message, plaintext, &err)) {
            previous.removeAt(i);
            record.promoteState(promoted);
            return true;
        }
    }
    if (error) *error = QLatin1String("no valid session: ") + firstError;
    return false;
}

bool SessionCipher::chainKeyFor(SessionState &state, const QByteArray &theirEphemeral, ChainKey *out, QString *error)
{
    if (state.hasReceiverChain(theirEphemeral)) {
        *out = state.receiverChainKey(theirEphemeral);
        return true;
    }
    // A new ratchet key from the peer: step the root key for their chain, then again with a
    // fresh key of ours for the next sending chain.
    const RootKey root = state.rootKey();
    const ECKeyPair ourEphemeral = state.senderRatchetKeyPair();
    if (!ourEphemeral.isValid()) { fail(error, "uninitialized session"); return false; }
    RootKey receiverRoot;
    ChainKey receiverChain;
    root.createChain(theirEphemeral, ourEphemeral, &receiverRoot, &receiverChain);
    const ECKeyPair ourNewEphemeral = Curve::generateKeyPair();
    RootKey senderRoot;
    ChainKey senderChain;
    receiverRoot.createChain(theirEphemeral, ourNewEphemeral, &senderRoot, &senderChain);

    state.setRootKey(senderRoot);
    state.addReceiverChain(theirEphemeral, receiverChain);
    const quint32 prev = state.senderChainKey().index;
    state.setPreviousCounter(prev > 0 ? prev - 1 : 0);
    state.setSenderChain(ourNewEphemeral, senderChain);
    *out = receiverChain;
    return true;
}

bool SessionCipher::messageKeysFor(SessionState &state, const QByteArray &theirEphemeral, ChainKey chainKey, quint32 counter,
                                   MessageKeys *out, QString *error)
{
    if (chainKey.index > counter) {
        if (state.hasMessageKeys(theirEphemeral, counter)) {
            *out = state.removeMessageKeys(theirEphemeral, counter);
            return true;
        }
        fail(error, "duplicate message (old counter)");
        return false;
    }
    if (counter - chainKey.index > MAX_FUTURE_MESSAGES) { fail(error, "over 2000 messages into the future"); return false; }
    while (chainKey.index < counter) {
        state.setMessageKeys(theirEphemeral, chainKey.messageKeys());
        chainKey = chainKey.next();
    }
    state.setReceiverChainKey(theirEphemeral, chainKey.next());
    *out = chainKey.messageKeys();
    return true;
}

bool SessionCipher::decryptWithState(SessionState &state, const SignalMessage &message, QByteArray *plaintext, QString *error)
{
    if (!state.hasSenderChain()) { fail(error, "uninitialized session"); return false; }
    if (message.version() != state.sessionVersion()) { fail(error, "message version mismatch"); return false; }

    const QByteArray theirEphemeral = message.senderRatchetKey();
    ChainKey chainKey;
    if (!chainKeyFor(state, theirEphemeral, &chainKey, error)) return false;
    MessageKeys keys;
    if (!messageKeysFor(state, theirEphemeral, chainKey, message.counter(), &keys, error)) return false;

    if (!message.verifyMac(state.remoteIdentityKey(), state.localIdentityKey(), keys.macKey)) { fail(error, "bad mac"); return false; }
    if (!aesCbcDecrypt(keys.cipherKey, keys.iv, message.body(), plaintext)) { fail(error, "decryption failed"); return false; }

    state.clearUnacknowledgedPreKeyMessage();
    return true;
}

} // namespace Signal
