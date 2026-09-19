# SimpleJabber

An XMPP (Jabber) chat client with **OMEMO** end-to-end encryption for **Symbian Belle**
(and Anna), written in Qt 4.7.4 / Qt Quick 1.1 with the Symbian Qt Quick Components.

Ported from [JabberWP](https://github.com/Symnok/JabberWP8.1) (Windows Phone 8.1), MIT
licensed. The WP client used the C# libsignal port; here the Signal protocol and the
Curve25519 / AES / SHA primitives are reimplemented in portable C/C++ (no external crypto
library), so the whole app builds with the stock Symbian GCCE toolchain.

Tested against **xabber.org**, interoperating with Conversations (Android) at the protocol
level.

## Why the Qt TLS patch is needed

A 2011 phone cannot reach a modern XMPP server on its own: stock Qt 4.7 on Symbian speaks
TLS 1.0 only, and the certificate store predates today's CAs. SimpleJabber, like SimpleOKM,
relies on the **Qt TLS patch** (https://nnproject.cc/qtls, sources at
[shinovon/qt-patches](https://github.com/shinovon/qt-patches)) — a `QtNetwork.dll` with
OpenSSL 1.0.2u linked in — installed on the phone once. Trust is the app's own: a bundled
root store (`certs/roots.pem`, the Mozilla set) plus **trust-on-first-use** pinning — an
unverifiable certificate raises a prompt showing its SHA-256 fingerprint, and accepting it
pins that certificate for that server. Without the patch the login page says TLS is
unavailable (`QSslSocket::supportsSsl()` is false).

## What it does

- **Connect**: TCP, STARTTLS, SASL PLAIN, resource binding, legacy session; auto-reconnect
  with backoff. Editable account (JID, password, optional host/port).
- **Roster and presence**: contacts with an availability dot, live presence, newest/unread
  first. Add a contact, rename (server-side roster edit), remove. Accept or decline incoming
  subscription requests; accepting also subscribes back.
- **Chat**: send and receive text, history kept on the phone (newest 500 / six months per
  chat), day separators, delivery/failed marks. Long-press a message to copy text or open a
  link.
- **Pictures** (XEP-0363 HTTP upload): send from the phone (scaled to 1280 px, JPEG); received
  image links show inline (tap for full screen); other links are tappable.
- **OMEMO** (XEP-0384, `eu.siacs.conversations.axolotl`), **per contact**: a lock toggle in
  the chat. Encrypts **text and pictures** (pictures as `aesgcm://` via encrypted HTTP
  upload). Publishes the device list and bundle over PEP, builds Double Ratchet sessions from
  contacts' bundles, and shows your own and the contact's identity fingerprints. Blind trust
  (every device is encrypted for) — the fingerprint screen is there to compare out of band.
- **Settings**: app language (system / English / Russian), OMEMO device id and fingerprint,
  about. Exit.

Encryption is per-conversation and opt-in, off by default. The TLS transport protects
everything; OMEMO adds end-to-end encryption on top for text and pictures in the chats where
it is switched on. Encrypted chats and messages are marked with a small green padlock.

### PEP on real servers (the "not encrypted for this device" fix)

ejabberd (xabber.org and others) keeps a PEP node's item history, so a plain fetch of a
contact's OMEMO device-list or bundle can return several `<item>`s. Reading the wrong
(stale) one makes the sender miss the contact's current device, and the message arrives as
"Message was not encrypted for this device" on the far end. SimpleJabber requests
`max_items='1'` and always reads the item tagged `id='current'` (or the newest), and it
publishes its own device-list and bundle with the open access model - reconfiguring the
node to open when the server created it closed - so a contact who is not subscribed (and
Conversations) can read them. A device we have decrypted a message from is also remembered
for the session, so replies reach it even when its node is briefly unreadable.

### Not in this port

- Background operation and notifications — a self-signed Symbian app has no background
  service; the app receives only while open (this was JabberWP's location-trick / periodic
  agent, both platform-specific).
- Group chat (MUC), message carbons/MAM, voice/video.
- OMEMO for anything other than text and pictures.

## Layout

```
SimpleJabber.pro          the phone app (Symbian and Qt Simulator kits)
signal.pri / xmpp.pri     the reusable layers, shared with the tests
src/crypto/               portable C crypto, no dependencies
  third_party/tweetnacl.* TweetNaCl (public domain): Curve25519, Ed25519, SHA-512
  xeddsa.*                X25519 agreement + XEdDSA sign/verify on TweetNaCl
  sha256.*                SHA-256, HMAC-SHA256, HKDF-SHA256
  aes.*                   AES-128/256, CBC/PKCS#7 and GCM
src/signal/               the Signal protocol (libsignal-compatible on the wire)
  curve, protobuf, messages, ratchet, state, store, session
src/xmpp/                 xmlelement, xmppstream (TLS + stanza reader), xmppclient
src/omemo/omemomanager.*  XEP-0384: PEP device lists/bundles, encrypt/decrypt, aesgcm media
src/app/                  networkmanager, messagestore, mediacache, imageuploader,
                          contactsmodel, messagesmodel, appcontroller ("app" in QML)
src/main.cpp              QDeclarativeView + Qt Quick Components, file logger, translations
qml/                      Login, Contacts, Chat (+MessageDelegate), TextInput, Image, Settings
certs/roots.pem           the bundled trust store (compiled in)
tests/                    crypto_test, signal_test (offline), xmpp_test (against a server)
tools/testserver.py       a tiny local XMPP+PEP+upload server for desktop testing
build-symbian.cmd         command-line phone build (in-source; see below)
```

The crypto and Signal layers have **no Qt UI dependency** and no platform code beyond a
random source, so they are exercised by desktop unit tests before ever touching the phone.

## Building

### Phone (Symbian Belle / Anna)

Same toolchain and rules as SimpleOKM-Symbian: Qt SDK 1.2.1, the **Qt 4.7.4 for Symbian
Anna/Belle** target, GCCE 4.4.1, SBSv2; the project must be on the same drive as the SDK, and
Qt for Symbian builds **in-source only**.

```
build-symbian.cmd              -> SimpleJabber.sis            (self-signed, Belle)
build-symbian.cmd installer    -> SimpleJabber_installer.sis  (Smart Installer, for Anna)
build-symbian.cmd clean
```

Or open `SimpleJabber.pro` in Qt Creator with the Symbian Device kit and build Release.

Self-signed (UID `0xE31A0C4C`, unprotected range); capabilities `NetworkServices
ReadUserData WriteUserData`, all user-grantable, so it installs on a phone that accepts
self-signed packages — which the Qt TLS patch already requires. Belle has Qt 4.7.4 and the
Qt Quick Components built in; on Anna the Smart-Installer package fetches the components (or
install the `Qt Quick components` sis from the SDK first).

### Qt Simulator (run it on the PC)

Build `SimpleJabber.pro` with the Simulator kit, start
`Simulator\Application\simulator.exe`, run the exe. For a live session put OpenSSL 1.0.x
`libeay32.dll`/`ssleay32.dll` next to it (the SDK's own are 0.9.8 and too old). Point it at
`tools/testserver.py` (host `127.0.0.1`), which serves TLS + roster + PEP + HTTP upload and
has users `alice@ / bob@ / carol@test.local` (any password).

### Tests

```
tests/crypto_test    vectors: FIPS 180-4 / RFC 4231 / RFC 5869 / FIPS 197 / NIST GCM /
                     RFC 7748 / libsignal's XEdDSA signature and agreement vectors
tests/signal_test    two stores play Alice and Bob: X3DH, pre key + normal messages, ratchet
                     steps, out-of-order delivery, duplicate rejection, persistence, re-keying
tests/xmpp_test      against a server: connect (with the cert prompt), plaintext, OMEMO both
                     ways, offline delivery. Build with desktop Qt, then:
                       xmpp_test                 local tools/testserver.py
                       xmpp_test --bot bob       an echo bot, to drive the UI by hand
                       xmpp_test --real creds    two "jid password [host] [port]" lines
```

Each qmake-builds with `signal.pri` / `xmpp.pri`; `win32:LIBS += -ladvapi32` (CryptGenRandom)
is already in `signal.pri`.

## Notes for the phone

- **Access point**: the app opens a `QNetworkSession` on the default configuration at start,
  so the phone asks for a connection once rather than per request.
- **Clock**: certificate validation needs a roughly correct date; a wrong year reads as a
  certificate error on the login page (accept the pin prompt, or fix the clock).
- **Log**: warnings and QML errors go to `simplejabber.log` in the app's data folder — the
  first place to look if something misbehaves on the device.
- Saved/received pictures live in the app cache; sent pictures are shown from there
  immediately.

## Security note

The crypto here (TweetNaCl aside, which is well-reviewed) is a from-scratch reimplementation
written for this port and validated against published test vectors and against Conversations
over the wire. It has not had an independent audit. It is wire-compatible with OMEMO and uses
blind trust like the reference clients; treat the fingerprint screen as the way to verify a
contact out of band.
