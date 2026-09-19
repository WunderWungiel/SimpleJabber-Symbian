// SimpleJabber - Signal protocol round-trip test (desktop). Two file stores play Alice and
// Bob: bundle exchange, pre key message, replies, ratchet steps, out-of-order delivery,
// duplicate rejection, persistence across reloads, and the protobuf/wire helpers.
#include "signal/curve.h"
#include "signal/messages.h"
#include "signal/protobuf.h"
#include "signal/session.h"
#include "signal/store.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <cstdio>

using namespace Signal;

static QTextStream out(stdout);
static int failures = 0;

// Qt 4 has no QDir::removeRecursively.
static void removeTree(const QString &path)
{
    QDir dir(path);
    if (!dir.exists()) return;
    const QFileInfoList entries = dir.entryInfoList(QDir::NoDotAndDotDot | QDir::Files | QDir::Dirs | QDir::Hidden);
    for (int i = 0; i < entries.size(); ++i) {
        if (entries.at(i).isDir()) removeTree(entries.at(i).absoluteFilePath());
        else QFile::remove(entries.at(i).absoluteFilePath());
    }
    dir.rmdir(path);
}

#define CHECK(cond, name) do { if (cond) out << "ok   " << name << endl; else { out << "FAIL " << name << endl; ++failures; } } while (0)

static PreKeyBundle bundleOf(FileStore &store, quint32 signedId, quint32 preKeyId)
{
    PreKeyBundle b;
    b.registrationId = store.deviceId();
    b.deviceId = store.deviceId();
    b.identityKey = store.identityKeyPair().publicKey;
    SignedPreKeyRecord spk;
    store.loadSignedPreKey(signedId, &spk);
    b.signedPreKeyId = spk.id;
    b.signedPreKeyPublic = spk.keyPair.publicKey;
    b.signedPreKeySignature = spk.signature;
    if (preKeyId) {
        PreKeyRecord pk;
        store.loadPreKey(preKeyId, &pk);
        b.preKeyId = pk.id;
        b.preKeyPublic = pk.keyPair.publicKey;
    }
    return b;
}

static void provision(FileStore &store)
{
    store.loadOrCreateOwnDevice();
    SignedPreKeyRecord spk;
    spk.id = 1;
    spk.timestamp = 0;
    spk.keyPair = Curve::generateKeyPair();
    spk.signature = Curve::sign(store.identityKeyPair().privateKey, Curve::encodePublic(spk.keyPair.publicKey));
    store.storeSignedPreKey(1, spk);
    for (quint32 i = 1; i <= 5; ++i) {
        PreKeyRecord pk;
        pk.id = i;
        pk.keyPair = Curve::generateKeyPair();
        store.storePreKey(i, pk);
    }
}

// Encrypt from `from` to `to` and decrypt on the other side; returns the plaintext seen.
static QByteArray roundTrip(Store &from, const Address &toAddr, Store &to, const Address &fromAddr, const QByteArray &text, bool *wasPreKey)
{
    SessionCipher sender(&from, toAddr);
    QByteArray wire;
    bool preKey = false;
    QString err;
    if (!sender.encrypt(text, &wire, &preKey, &err)) { out << "  encrypt error: " << err << endl; return QByteArray(); }
    if (wasPreKey) *wasPreKey = preKey;
    SessionCipher receiver(&to, fromAddr);
    QByteArray plain;
    bool ok = preKey ? receiver.decryptPreKeyMessage(PreKeySignalMessage::parse(wire), &plain, &err)
                     : receiver.decryptMessage(SignalMessage::parse(wire), &plain, &err);
    if (!ok) { out << "  decrypt error: " << err << endl; return QByteArray(); }
    return plain;
}

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const QString base = QDir::tempPath() + QLatin1String("/sj-signal-test");
    removeTree(base);

    // -- protobuf --
    {
        ProtoWriter w;
        w.varint(1, 300);
        w.bytes(2, QByteArray("hello"));
        w.varint(6, 0xFFFFFFFFULL);
        CHECK(w.result().toHex() == "08ac02120568656c6c6f30ffffffff0f", "protobuf encoding");
        ProtoReader r(w.result());
        CHECK(r.ok() && r.varint(1) == 300 && r.bytes(2) == "hello" && r.varint(6) == 0xFFFFFFFFULL && !r.has(3), "protobuf decoding");
        ProtoReader bad(QByteArray::fromHex("1205686568"));
        CHECK(!bad.ok(), "protobuf truncated rejected");
    }

    // -- key encoding + signature --
    {
        const ECKeyPair kp = Curve::generateKeyPair();
        const QByteArray enc = Curve::encodePublic(kp.publicKey);
        CHECK(enc.size() == 33 && enc.at(0) == 0x05 && Curve::decodePublic(enc) == kp.publicKey, "public key encoding");
        const QByteArray sig = Curve::sign(kp.privateKey, enc);
        CHECK(sig.size() == 64 && Curve::verify(kp.publicKey, enc, sig), "sign/verify");
        CHECK(!Curve::verify(kp.publicKey, enc + "x", sig), "verify rejects altered message");
    }

    FileStore alice(base + QLatin1String("/alice"));
    FileStore bob(base + QLatin1String("/bob"));
    provision(alice);
    provision(bob);
    const Address aliceAddr(QLatin1String("alice@example.com"), alice.deviceId());
    const Address bobAddr(QLatin1String("bob@example.com"), bob.deviceId());
    CHECK(alice.deviceId() != 0 && alice.identityKeyPair().isValid(), "own device generated");

    // Alice builds a session from Bob's bundle.
    {
        SessionBuilder builder(&alice, bobAddr);
        QString err;
        PreKeyBundle b = bundleOf(bob, 1, 3);
        CHECK(builder.processPreKeyBundle(b, &err), "process bundle");
        b.signedPreKeySignature[0] = b.signedPreKeySignature[0] ^ 1;
        CHECK(!builder.processPreKeyBundle(b, &err), "bad bundle signature rejected");
        CHECK(alice.containsSession(bobAddr) && !bob.containsSession(aliceAddr), "alice has a session, bob not yet");
    }

    // First message: a pre key message. Bob consumes pre key 3.
    bool preKey = false;
    CHECK(roundTrip(alice, bobAddr, bob, aliceAddr, "hello bob", &preKey) == "hello bob" && preKey, "prekey message alice->bob");
    CHECK(!bob.containsPreKey(3) && bob.containsPreKey(2), "one-time pre key consumed");
    CHECK(roundTrip(alice, bobAddr, bob, aliceAddr, "second", &preKey) == "second" && preKey, "second message still prekey (unacknowledged)");

    // Bob replies: ratchet step on Alice's side, and Alice's pending pre key state clears.
    CHECK(roundTrip(bob, aliceAddr, alice, bobAddr, "hi alice", &preKey) == "hi alice" && !preKey, "reply bob->alice");
    CHECK(roundTrip(alice, bobAddr, bob, aliceAddr, "third", &preKey) == "third" && !preKey, "alice->bob after reply is a plain message");

    // A burst in both directions.
    bool okBurst = true;
    for (int i = 0; i < 20; ++i) {
        const QByteArray t = "msg" + QByteArray::number(i);
        if (roundTrip(i % 3 ? alice : bob, i % 3 ? bobAddr : aliceAddr, i % 3 ? bob : alice, i % 3 ? aliceAddr : bobAddr, t, 0) != t) okBurst = false;
    }
    CHECK(okBurst, "20 alternating messages");

    // Out of order: encrypt three, deliver 3, 1, 2; then a duplicate of 1 must be refused.
    {
        SessionCipher sender(&alice, bobAddr);
        QByteArray w1, w2, w3;
        bool pk;
        QString err;
        sender.encrypt("one", &w1, &pk, &err);
        sender.encrypt("two", &w2, &pk, &err);
        sender.encrypt("three", &w3, &pk, &err);
        SessionCipher receiver(&bob, aliceAddr);
        QByteArray p1, p2, p3, dup;
        bool ok3 = receiver.decryptMessage(SignalMessage::parse(w3), &p3, &err);
        bool ok1 = receiver.decryptMessage(SignalMessage::parse(w1), &p1, &err);
        bool ok2 = receiver.decryptMessage(SignalMessage::parse(w2), &p2, &err);
        CHECK(ok1 && ok2 && ok3 && p1 == "one" && p2 == "two" && p3 == "three", "out-of-order delivery");
        CHECK(!receiver.decryptMessage(SignalMessage::parse(w1), &dup, &err), "duplicate rejected");
    }

    // Persistence: reload both stores from disk and keep chatting.
    {
        FileStore alice2(base + QLatin1String("/alice"));
        FileStore bob2(base + QLatin1String("/bob"));
        alice2.loadOrCreateOwnDevice();
        bob2.loadOrCreateOwnDevice();
        CHECK(alice2.deviceId() == alice.deviceId() && alice2.identityKeyPair().publicKey == alice.identityKeyPair().publicKey, "identity reloaded");
        CHECK(roundTrip(bob2, aliceAddr, alice2, bobAddr, "after reload", 0) == "after reload", "session survives reload");
        CHECK(alice2.subDeviceSessions(bobAddr.name).contains(bob.deviceId()), "sub device sessions listed");
    }

    // Tampering: a flipped ciphertext byte fails the MAC.
    {
        SessionCipher sender(&alice, bobAddr);
        QByteArray w;
        bool pk;
        QString err;
        sender.encrypt("tamper", &w, &pk, &err);
        w[w.size() - 12] = w[w.size() - 12] ^ 1;
        SessionCipher receiver(&bob, aliceAddr);
        QByteArray p;
        CHECK(!receiver.decryptMessage(SignalMessage::parse(w), &p, &err), "tampered message rejected");
    }

    // A second session from a fresh bundle (e.g. Bob reinstalled): Alice's old state is
    // archived, and the new pre key message goes through.
    {
        SessionBuilder builder(&alice, bobAddr);
        QString err;
        CHECK(builder.processPreKeyBundle(bundleOf(bob, 1, 5), &err), "re-process bundle");
        CHECK(roundTrip(alice, bobAddr, bob, aliceAddr, "new session", &preKey) == "new session" && preKey, "new session prekey message");
        CHECK(roundTrip(bob, aliceAddr, alice, bobAddr, "back", &preKey) == "back", "reply on new session");
    }

    removeTree(base);
    out << (failures ? "FAILED" : "ALL PASSED") << " (" << failures << " failures)" << endl;
    return failures ? 1 : 0;
}
