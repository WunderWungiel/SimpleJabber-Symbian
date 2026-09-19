// SimpleJabber - end-to-end test against tools/testserver.py: two clients (alice, bob) in
// one process connect (self-signed certificate -> pin -> reconnect), exchange plaintext,
// bring OMEMO up, and exchange encrypted messages both ways, including a pre key message,
// an offline-queued message and a second OMEMO session after a "reinstall".
//
//   python tools/testserver.py            (in another terminal)
//   xmpp_test [host] [port]               default 127.0.0.1 5222
#include "xmpp/xmppclient.h"
#include "omemo/omemomanager.h"
#include "crypto/xeddsa.h"
#include "signal/curve.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QTimer>
#include <QStringList>
#include <QRegExp>
#include <cstdio>
#include <cstring>

static QTextStream out(stdout);
static int failures = 0;
#define CHECK(cond, name) do { if (cond) out << "ok   " << name << endl; else { out << "FAIL " << name << endl; ++failures; } } while (0)

static void naclRandom(unsigned char *o, unsigned long long n) { const QByteArray b = Signal::Curve::randomBytes(int(n)); memcpy(o, b.constData(), size_t(n)); }

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

class Peer : public QObject
{
    Q_OBJECT
public:
    Peer(const QString &name, const QString &host, int port, const QString &dir, const QString &jid = QString(), const QString &password = QString())
        : m_name(name), m_client(new XmppClient(this)), m_omemo(0), m_dir(dir), m_ready(false), m_pinned(false), m_reconnected(false)
    {
        m_account.jid = jid.isEmpty() ? name + QLatin1String("@test.local") : jid;
        m_account.password = password.isEmpty() ? QLatin1String("x") : password;
        m_account.host = host;
        m_account.port = quint16(port);
        m_account.resource = QLatin1String("sjtest");
        connect(m_client, SIGNAL(connectedToServer()), this, SLOT(onConnected()));
        connect(m_client, SIGNAL(closed(QString)), this, SLOT(onClosed(QString)));
        connect(m_client, SIGNAL(certificateRejected(QString,QString,QString,QString)), this, SLOT(onCert(QString,QString,QString,QString)));
        connect(m_client, SIGNAL(messageReceived(XmppMessage)), this, SLOT(onMessage(XmppMessage)));
        connect(m_client, SIGNAL(rosterReceived(QList<RosterItem>)), this, SLOT(onRoster(QList<RosterItem>)));
    }

    XmppClient *client() const { return m_client; }
    OmemoManager *omemo() const { return m_omemo; }
    bool ready() const { return m_ready; }
    QString jid() const { return m_account.jid; }
    QList<XmppMessage> received;
    QStringList roster;
    bool pinned() const { return m_pinned; }

    void start() { m_client->connectToServer(m_account); }
    void stop() { if (m_omemo) m_omemo->disable(); m_client->disconnectFromServer(); }
    void resetOmemo()
    {
        if (m_omemo) { m_omemo->disable(); m_omemo->deleteLater(); m_omemo = 0; }
        removeTree(m_dir);
    }

    void subscribeTo(const QString &jid) { m_client->addContact(jid, QString()); }

signals:
    void omemoReady(bool ok);

private slots:
    void onSubscription(const QString &jid) { m_client->answerSubscription(jid, true, true); }
    void onCert(const QString &host, const QString &fp, const QString &subject, const QString &errors)
    {
        out << "  [" << m_name << "] certificate rejected (" << subject << "): " << errors.left(60) << " -> pinning" << endl;
        XmppStream::setPinnedCertificate(host, fp);
        m_pinned = true;
    }
    void onClosed(const QString &reason)
    {
        out << "  [" << m_name << "] closed: " << reason << endl;
        if (m_pinned && !m_client->isConnected() && !m_reconnected) { m_reconnected = true; QTimer::singleShot(200, this, SLOT(start2())); }
    }
    void onConnected()
    {
        out << "  [" << m_name << "] connected as " << m_client->boundJid().full() << endl;
        if (m_omemo) { m_omemo->deleteLater(); m_omemo = 0; }
        m_omemo = new OmemoManager(m_client, m_client->boundJid().bare(), m_dir, this);
        connect(m_omemo, SIGNAL(enabledChanged(bool)), this, SLOT(onOmemo(bool)));
        m_omemo->enable();
    }
    void onOmemo(bool ok)
    {
        out << "  [" << m_name << "] OMEMO " << (ok ? "ready" : "FAILED") << " device " << m_omemo->ownDeviceId() << endl;
        m_ready = ok;
        emit omemoReady(ok);
    }
    void onMessage(const XmppMessage &m)
    {
        out << "  [" << m_name << "] message from " << m.contactJid << (m.encrypted ? " [OMEMO]" : "") << ": " << m.body << endl;
        received.append(m);
    }
    void onRoster(const QList<RosterItem> &items)
    {
        for (int i = 0; i < items.size(); ++i) if (!roster.contains(items.at(i).jid)) roster.append(items.at(i).jid);
    }
public slots:
    void start2() { start(); }

private:
    QString m_name;
    XmppClient *m_client;
    OmemoManager *m_omemo;
    XmppAccount m_account;
    QString m_dir;
    bool m_ready;
    bool m_pinned;
    bool m_reconnected;
};

/// --bot <name>: stays online as <name> and answers every message with "echo: ...",
/// encrypted when the incoming one was. For driving the UI by hand.
class EchoBot : public QObject
{
    Q_OBJECT
public:
    explicit EchoBot(Peer *p) : m_peer(p)
    {
        connect(p->client(), SIGNAL(messageReceived(XmppMessage)), this, SLOT(onMessage(XmppMessage)));
    }
private slots:
    void onMessage(const XmppMessage &m)
    {
        const QString reply = QLatin1String("echo: ") + m.body;
        if (m.encrypted && m_peer->omemo()) m_peer->omemo()->sendEncrypted(m.contactJid, reply, QLatin1String("e") + m.id);
        else m_peer->client()->sendMessage(m.contactJid, reply);
    }
private:
    Peer *m_peer;
};

class Script : public QObject
{
    Q_OBJECT
public:
    Script(Peer *a, Peer *b) : alice(a), bob(b), step(0), sendOk(false), real(false), subscribed(false)
    {
        connect(a, SIGNAL(omemoReady(bool)), this, SLOT(tick()));
        connect(b, SIGNAL(omemoReady(bool)), this, SLOT(tick()));
        QTimer::singleShot(60000, this, SLOT(timeout()));
    }
public slots:
    void tick()
    {
        if (!(alice->ready() && bob->ready())) return;
        if (real && step == 0 && !subscribed) {
            subscribed = true;
            alice->subscribeTo(bob->jid());
            bob->subscribeTo(alice->jid());
            out << "  subscribing the two accounts; waiting for presence + PEP access..." << endl;
            QTimer::singleShot(6000, this, SLOT(tick()));
            return;
        }
        if (step == 0) {
            step = 1;
            if (!real) CHECK(alice->pinned() || bob->pinned(), "self-signed certificate rejected, pinned, reconnected");
            else CHECK(!alice->pinned() && !bob->pinned(), "server certificate verified against the bundled roots");
            if (!real) CHECK(alice->roster.contains(QLatin1String("bob@test.local")), "roster received");
            // plaintext
            alice->client()->sendMessage(bob->jid(), QLatin1String("plain hello"));
            QTimer::singleShot(real ? 3000 : 500, this, SLOT(tick()));
            return;
        }
        if (step == 1) {
            step = 2;
            CHECK(!bob->received.isEmpty() && bob->received.last().body == QLatin1String("plain hello") && !bob->received.last().encrypted, "plaintext delivered");
            connect(alice->omemo(), SIGNAL(sendFinished(QString,bool,QString)), this, SLOT(onSent(QString,bool,QString)));
            alice->omemo()->sendEncrypted(bob->jid(), QString::fromUtf8("secret \xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82 1"), QLatin1String("m1"));
            return;
        }
        if (step == 2) {
            step = 3;
            CHECK(sendOk, "alice: OMEMO send reported ok");
            CHECK(!bob->received.isEmpty() && bob->received.last().encrypted && bob->received.last().body == QString::fromUtf8("secret \xD0\xBF\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82 1"), "bob decrypted the pre key message");
            connect(bob->omemo(), SIGNAL(sendFinished(QString,bool,QString)), this, SLOT(onSent(QString,bool,QString)));
            sendOk = false;
            bob->omemo()->sendEncrypted(alice->jid(), QLatin1String("reply 2"), QLatin1String("m2"));
            return;
        }
        if (step == 3) {
            step = 4;
            CHECK(sendOk, "bob: OMEMO reply reported ok");
            CHECK(!alice->received.isEmpty() && alice->received.last().encrypted && alice->received.last().body == QLatin1String("reply 2"), "alice decrypted the reply (ratchet step)");
            sendOk = false;
            alice->omemo()->sendEncrypted(bob->jid(), QLatin1String("third 3"), QLatin1String("m3"));
            return;
        }
        if (step == 4) {
            step = 5;
            CHECK(bob->received.last().body == QLatin1String("third 3") && bob->received.last().encrypted, "bob decrypted a plain SignalMessage");
            // Bob goes offline; alice sends; bob comes back and gets it from the offline queue.
            bob->stop();
            QTimer::singleShot(300, this, SLOT(tick()));
            return;
        }
        if (step == 5) {
            step = 6;
            sendOk = false;
            alice->omemo()->sendEncrypted(bob->jid(), QLatin1String("while you were away 4"), QLatin1String("m4"));
            return;
        }
        if (step == 6) {
            step = 7;
            CHECK(sendOk, "alice: send to offline bob ok (session on disk)");
            bob->start2();
            return;   // bob's omemoReady triggers tick again
        }
        if (step == 7) {
            step = 8;
            QTimer::singleShot(800, this, SLOT(tick()));
            return;
        }
        if (step == 8) {
            step = 9;
            CHECK(bob->received.last().body == QLatin1String("while you were away 4") && bob->received.last().encrypted, "offline OMEMO message decrypted after reconnect");
            if (real) { finish(); return; }   // no throw-away device ids on a real account
            // Bob "reinstalls": new identity + device id; alice must fetch the new bundle.
            bob->stop();
            bob->resetOmemo();
            QTimer::singleShot(300, bob, SLOT(start2()));
            return;
        }
        if (step == 9) {
            step = 10;
            connect(alice->omemo(), SIGNAL(sendFinished(QString,bool,QString)), this, SLOT(onSent(QString,bool,QString)), Qt::UniqueConnection);
            sendOk = false;
            alice->omemo()->sendEncrypted(bob->jid(), QLatin1String("after reinstall 5"), QLatin1String("m5"));
            return;
        }
        if (step == 10) {
            step = 11;
            CHECK(sendOk, "alice: send after bob's reinstall ok");
            CHECK(bob->received.last().body == QLatin1String("after reinstall 5"), "bob's new device decrypted (new session)");
            finish();
        }
    }
    void onSent(const QString &id, bool ok, const QString &error)
    {
        out << "  send " << id << (ok ? " ok" : " FAILED: " + error) << endl;
        sendOk = ok;
        QTimer::singleShot(real ? 3000 : 700, this, SLOT(tick()));
    }
    void timeout() { out << "TIMEOUT at step " << step << endl; ++failures; finish(); }
    void finish()
    {
        alice->stop();
        bob->stop();
        out << (failures ? "FAILED" : "ALL PASSED") << " (" << failures << " failures)" << endl;
        out.flush();
        QTimer::singleShot(300, qApp, SLOT(quit()));
    }
    void setRealServer(bool r) { real = r; }
private:
    Peer *alice, *bob;
    int step;
    bool sendOk;
    bool real;
    bool subscribed;
};

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    out.setCodec("UTF-8");
    nacl_set_random_source(naclRandom);
    const QString host = argc > 1 ? QString::fromLatin1(argv[1]) : QLatin1String("127.0.0.1");
    const int port = argc > 2 ? atoi(argv[2]) : 5222;
    const QString base = QDir::tempPath() + QLatin1String("/sj-xmpp-test");

    if (argc > 2 && QString::fromLatin1(argv[1]) == QLatin1String("--real")) {
        // --real creds.txt: two "jid password [host] [port]" lines; runs the script against
        // a real server (the certificate must verify against the bundled roots).
        QFile f(QString::fromLocal8Bit(argv[2]));
        if (!f.open(QIODevice::ReadOnly)) { out << "cannot read creds" << endl; return 1; }
        const QStringList lines = QString::fromUtf8(f.readAll()).split(QRegExp(QLatin1String("\r?\n")), QString::SkipEmptyParts);
        if (lines.size() < 2) { out << "need two accounts" << endl; return 1; }
        const QStringList a = lines.at(0).split(QLatin1Char(' '), QString::SkipEmptyParts);
        const QStringList b = lines.at(1).split(QLatin1Char(' '), QString::SkipEmptyParts);
        removeTree(base);
        Peer alice(QLatin1String("A"), a.value(2), a.value(3, QLatin1String("5222")).toInt(), base + QLatin1String("/A"), a.at(0), a.at(1));
        Peer bob(QLatin1String("B"), b.value(2), b.value(3, QLatin1String("5222")).toInt(), base + QLatin1String("/B"), b.at(0), b.at(1));
        Script script(&alice, &bob);
        script.setRealServer(true);
        alice.start();
        bob.start();
        const int rc = app.exec();
        removeTree(base);
        return failures ? 1 : rc;
    }
    if (argc > 2 && QString::fromLatin1(argv[1]) == QLatin1String("--bot")) {
        const QString name = QString::fromLatin1(argv[2]);
        Peer bot(name, argc > 3 ? QString::fromLatin1(argv[3]) : QLatin1String("127.0.0.1"), argc > 4 ? atoi(argv[4]) : 5222, base + QLatin1String("/bot-") + name);
        EchoBot echo(&bot);
        out << "echo bot " << name << "@test.local running; Ctrl+C to stop" << endl;
        bot.start();
        return app.exec();
    }
    removeTree(base);

    Peer alice(QLatin1String("alice"), host, port, base + QLatin1String("/alice"));
    Peer bob(QLatin1String("bob"), host, port, base + QLatin1String("/bob"));
    Script script(&alice, &bob);
    alice.start();
    bob.start();
    const int rc = app.exec();
    removeTree(base);
    return failures ? 1 : rc;
}

#include "main.moc"
