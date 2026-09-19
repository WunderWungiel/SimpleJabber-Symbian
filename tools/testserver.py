#!/usr/bin/env python3
"""A tiny XMPP server for testing SimpleJabber on the desktop. NOT for real use.

Implements just enough of RFC 6120/6121 and the XEPs the app needs:
  - STARTTLS with a self-signed certificate (exercises the "trust this certificate" prompt)
  - SASL PLAIN (any password for the users listed below), resource binding, legacy session
  - roster (everyone knows everyone, subscription "both"), roster set / rename / remove
  - presence broadcast, subscription requests forwarded
  - message routing to a bare JID's connected resources (offline messages queued)
  - PEP pubsub: publish / retrieve items per (user, node), publish-options and affiliations
    accepted, device-list change notifications pushed to every connected user
  - disco#items / disco#info advertising upload.<domain> with XEP-0363, slot requests, and an
    HTTP server on 8443 that stores PUT bodies and serves them back on GET (plain http on
    8081 as well)

Usage:  python testserver.py [domain] [xmpp-port]
        default domain "test.local", port 5222; users alice@ / bob@ / carol@
"""
import asyncio
import base64
import datetime
import os
import ssl
import sys
import uuid
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "test.local"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5222
USERS = ["alice", "bob", "carol"]
UPLOAD_HOST = "upload." + DOMAIN
HTTP_PORT = 8081
HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "testserver.crt")
KEY = os.path.join(HERE, "testserver.key")

NS = {
    "client": "jabber:client", "stream": "http://etherx.jabber.org/streams",
    "tls": "urn:ietf:params:xml:ns:xmpp-tls", "sasl": "urn:ietf:params:xml:ns:xmpp-sasl",
    "bind": "urn:ietf:params:xml:ns:xmpp-bind", "session": "urn:ietf:params:xml:ns:xmpp-session",
    "roster": "jabber:iq:roster", "items": "http://jabber.org/protocol/disco#items",
    "info": "http://jabber.org/protocol/disco#info", "upload": "urn:xmpp:http:upload:0",
    "pubsub": "http://jabber.org/protocol/pubsub", "owner": "http://jabber.org/protocol/pubsub#owner",
    "event": "http://jabber.org/protocol/pubsub#event",
}


def ensure_cert():
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    # openssl is on PATH with Git for Windows; a 10-year self-signed cert for the domain.
    os.system(f'openssl req -x509 -newkey rsa:2048 -nodes -keyout "{KEY}" -out "{CERT}" -days 3650 '
              f'-subj "/CN={DOMAIN}" -addext "subjectAltName=DNS:{DOMAIN},DNS:{UPLOAD_HOST},DNS:localhost" >nul 2>&1')


class State:
    def __init__(self):
        self.sessions = {}      # full jid -> Session
        self.rosters = {u: {} for u in USERS}   # user -> {bare: {name, subscription}}
        self.pep = {}           # (bare, node) -> [item xml string]  (history, oldest first)
        self.offline = {}       # bare -> [stanza xml]
        self.files = {}         # path -> bytes
        self.names = {}         # (owner, contact) -> name
        for u in USERS:
            for v in USERS:
                if u != v:
                    self.rosters[u][f"{v}@{DOMAIN}"] = {"name": "", "subscription": "both"}


STATE = State()


class Session:
    def __init__(self, reader, writer, tls_ctx):
        self.reader, self.writer, self.tls_ctx = reader, writer, tls_ctx
        self.user = None
        self.resource = None
        self.encrypted = False
        self.depth = 0
        self.parser = None
        self.queue = []

    @property
    def bare(self):
        return f"{self.user}@{DOMAIN}"

    @property
    def full(self):
        return f"{self.bare}/{self.resource}"

    def send(self, text):
        try:
            self.writer.write(text.encode("utf-8"))
        except Exception:
            pass

    async def run(self):
        peer = self.writer.get_extra_info("peername")
        print(f"[conn] {peer}")
        try:
            await self.stream_loop()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as e:
            print("[error]", repr(e))
        finally:
            if self.user and self.resource:
                STATE.sessions.pop(self.full, None)
                self.broadcast_presence(unavailable=True)
                print(f"[gone] {self.full}")
            try:
                self.writer.close()
            except Exception:
                pass

    def new_parser(self):
        # A synthetic root so prefixes/default namespaces resolve like a real stream.
        self.parser = ET.XMLPullParser(events=("start", "end"))
        self.parser.feed(f"<stream:stream xmlns='jabber:client' xmlns:stream='{NS['stream']}'>")
        for _ in self.parser.read_events():
            pass
        self.depth = 0
        self.queue = []

    def feed(self, text):
        self.parser.feed(text)
        for ev, el in self.parser.read_events():
            if ev == "start":
                self.depth += 1
            elif ev == "end":
                self.depth -= 1
                if self.depth == 0:
                    self.queue.append(el)

    async def read_stanza(self):
        """Returns the next complete top-level element; handles stream (re)opens."""
        if self.parser is None:
            self.new_parser()
        while True:
            if self.queue:
                return self.queue.pop(0)
            data = await self.reader.read(4096)
            if not data:
                raise ConnectionError("closed")
            text = data.decode("utf-8", errors="replace")
            while "<stream:stream" in text:
                idx = text.index("<stream:stream")
                end = text.index(">", idx)
                before, text = text[:idx], text[end + 1:]
                if before.strip() and not before.strip().startswith("<?xml"):
                    self.feed(before)
                self.new_parser()
                self.on_stream_open()
            if "</stream:stream>" in text:
                raise ConnectionError("stream closed by client")
            if text.strip():
                self.feed(text)

    def on_stream_open(self):
        sid = uuid.uuid4().hex[:12]
        self.send(f"<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='{NS['stream']}' "
                  f"from='{DOMAIN}' id='{sid}' version='1.0'>")
        if not self.encrypted:
            self.send(f"<stream:features><starttls xmlns='{NS['tls']}'><required/></starttls></stream:features>")
        elif not self.user:
            self.send(f"<stream:features><mechanisms xmlns='{NS['sasl']}'><mechanism>PLAIN</mechanism></mechanisms></stream:features>")
        else:
            self.send(f"<stream:features><bind xmlns='{NS['bind']}'/><session xmlns='{NS['session']}'/></stream:features>")

    async def stream_loop(self):
        while True:
            el = await self.read_stanza()
            tag = el.tag
            if tag == f"{{{NS['tls']}}}starttls":
                self.send(f"<proceed xmlns='{NS['tls']}'/>")
                await self.writer.drain()
                await self.writer.start_tls(self.tls_ctx)
                self.encrypted = True
                print("[tls] established")
            elif tag == f"{{{NS['sasl']}}}auth":
                raw = base64.b64decode((el.text or "").strip())
                parts = raw.split(b"\0")
                user = parts[1].decode() if len(parts) >= 2 else ""
                if user in USERS:
                    self.user = user
                    self.send(f"<success xmlns='{NS['sasl']}'/>")
                    print(f"[auth] {user}")
                else:
                    self.send(f"<failure xmlns='{NS['sasl']}'><not-authorized/></failure>")
            elif tag == f"{{{NS['client']}}}iq":
                self.handle_iq(el)
            elif tag == f"{{{NS['client']}}}presence":
                self.handle_presence(el)
            elif tag == f"{{{NS['client']}}}message":
                self.handle_message(el)

    # -- iq --
    def handle_iq(self, el):
        iq_id = el.get("id", "")
        typ = el.get("type", "")
        to = el.get("to", "")
        child = el[0] if len(el) else None
        ctag = child.tag if child is not None else ""

        if ctag == f"{{{NS['bind']}}}bind":
            res = child.find(f"{{{NS['bind']}}}resource")
            self.resource = (res.text if res is not None and res.text else uuid.uuid4().hex[:8])
            STATE.sessions[self.full] = self
            self.send(f"<iq type='result' id='{iq_id}'><bind xmlns='{NS['bind']}'><jid>{self.full}</jid></bind></iq>")
            print(f"[bind] {self.full}")
            return
        if ctag == f"{{{NS['session']}}}session":
            self.send(f"<iq type='result' id='{iq_id}'/>")
            for st in STATE.offline.pop(self.bare, []):
                self.send(st)
            return
        if ctag == f"{{{NS['roster']}}}query":
            if typ == "get":
                items = "".join(f"<item jid='{j}' name='{ET._escape_attrib(v['name'])}' subscription='{v['subscription']}'/>"
                                for j, v in STATE.rosters[self.user].items())
                self.send(f"<iq type='result' id='{iq_id}'><query xmlns='{NS['roster']}'>{items}</query></iq>")
            else:
                for item in child.findall(f"{{{NS['roster']}}}item"):
                    jid = item.get("jid", "").lower()
                    if item.get("subscription") == "remove":
                        STATE.rosters[self.user].pop(jid, None)
                        push = f"<item jid='{jid}' subscription='remove'/>"
                    else:
                        entry = STATE.rosters[self.user].setdefault(jid, {"name": "", "subscription": "none"})
                        entry["name"] = item.get("name", "")
                        push = f"<item jid='{jid}' name='{ET._escape_attrib(entry['name'])}' subscription='{entry['subscription']}'/>"
                    for s in self.my_sessions():
                        s.send(f"<iq type='set' id='push{uuid.uuid4().hex[:6]}'><query xmlns='{NS['roster']}'>{push}</query></iq>")
                self.send(f"<iq type='result' id='{iq_id}'/>")
            return
        if ctag == f"{{{NS['items']}}}query":
            if to in ("", DOMAIN):
                self.send(f"<iq type='result' id='{iq_id}' from='{DOMAIN}'><query xmlns='{NS['items']}'>"
                          f"<item jid='{UPLOAD_HOST}' name='HTTP upload'/></query></iq>")
            else:
                self.send(f"<iq type='result' id='{iq_id}' from='{to}'><query xmlns='{NS['items']}'/></iq>")
            return
        if ctag == f"{{{NS['info']}}}query":
            feats = f"<feature var='{NS['upload']}'/>" if to == UPLOAD_HOST else "<feature var='http://jabber.org/protocol/pubsub#publish'/>"
            self.send(f"<iq type='result' id='{iq_id}' from='{to or DOMAIN}'><query xmlns='{NS['info']}'>{feats}</query></iq>")
            return
        if ctag == f"{{{NS['upload']}}}request":
            name = child.get("filename", "file.bin")
            path = f"/files/{uuid.uuid4().hex}/{name}"
            put = f"https://localhost:{HTTP_PORT + 1}{path}"
            get = f"https://localhost:{HTTP_PORT + 1}{path}"
            self.send(f"<iq type='result' id='{iq_id}' from='{UPLOAD_HOST}'><slot xmlns='{NS['upload']}'>"
                      f"<put url='{put}'/><get url='{get}'/></slot></iq>")
            print(f"[upload] slot {path}")
            return
        if ctag == f"{{{NS['pubsub']}}}pubsub":
            self.handle_pubsub(el, child, iq_id, to)
            return
        if ctag == f"{{{NS['owner']}}}pubsub":
            self.send(f"<iq type='result' id='{iq_id}'/>")   # affiliations: accepted
            return
        if typ in ("get", "set"):
            self.send(f"<iq type='error' id='{iq_id}'><error type='cancel'>"
                      f"<feature-not-implemented xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")

    def handle_pubsub(self, el, pubsub, iq_id, to):
        owner = (to or self.bare).split("/")[0].lower()
        publish = pubsub.find(f"{{{NS['pubsub']}}}publish")
        items = pubsub.find(f"{{{NS['pubsub']}}}items")
        if publish is not None:
            node = publish.get("node")
            item = publish.find(f"{{{NS['pubsub']}}}item")
            ET.register_namespace("", NS["pubsub"])
            content = "".join(ET.tostring(c, encoding="unicode") for c in item)
            # Keep a small history and DO NOT collapse to one item, mimicking an ejabberd
            # node that retains items - the "current" item is the newest (appended last).
            hist = STATE.pep.setdefault((self.bare, node), [])
            hist.append(content)
            if len(hist) > 4:
                del hist[0]
            self.send(f"<iq type='result' id='{iq_id}'><pubsub xmlns='{NS['pubsub']}'><publish node='{node}'>"
                      f"<item id='current'/></publish></pubsub></iq>")
            print(f"[pep] {self.bare} published {node} (history now {len(hist)})")
            if node.endswith("devicelist"):
                ev = (f"<message from='{self.bare}' type='headline' id='ev{uuid.uuid4().hex[:6]}'><event xmlns='{NS['event']}'>"
                      f"<items node='{node}'><item id='current'>{content}</item></items></event></message>")
                for s in list(STATE.sessions.values()):
                    s.send(ev.replace("<message ", f"<message to='{s.full}' ", 1))
            return
        if items is not None:
            node = items.get("node")
            hist = STATE.pep.get((owner, node))
            if not hist:
                self.send(f"<iq type='error' id='{iq_id}' from='{owner}'><error type='cancel'>"
                          f"<item-not-found xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>")
            else:
                # Oldest-first, only the last tagged id='current'. A client that reads the
                # first <item> gets a stale one; it must select id='current' (or the newest).
                body = ""
                for i, c in enumerate(hist):
                    iid = "current" if i == len(hist) - 1 else f"old{i}"
                    body += f"<item id='{iid}'>{c}</item>"
                self.send(f"<iq type='result' id='{iq_id}' from='{owner}'><pubsub xmlns='{NS['pubsub']}'><items node='{node}'>"
                          f"{body}</items></pubsub></iq>")
            return
        self.send(f"<iq type='result' id='{iq_id}'/>")

    # -- presence --
    def my_sessions(self):
        return [s for s in STATE.sessions.values() if s.user == self.user]

    def broadcast_presence(self, unavailable=False, show="", status=""):
        for s in list(STATE.sessions.values()):
            if s.user == self.user:
                continue
            inner = f"<show>{show}</show>" if show else ""
            inner += f"<status>{ET._escape_cdata(status)}</status>" if status else ""
            typ = " type='unavailable'" if unavailable else ""
            s.send(f"<presence from='{self.full}' to='{s.bare}'{typ}>{inner}</presence>")

    def handle_presence(self, el):
        typ = el.get("type", "")
        to = el.get("to", "")
        if typ in ("subscribe", "subscribed", "unsubscribe", "unsubscribed") and to:
            for s in list(STATE.sessions.values()):
                if s.bare == to.lower():
                    s.send(f"<presence from='{self.bare}' to='{to}' type='{typ}'/>")
            if typ == "subscribed":
                STATE.rosters.get(to.split("@")[0], {}).setdefault(self.bare, {"name": "", "subscription": "both"})["subscription"] = "both"
                STATE.rosters[self.user].setdefault(to.lower(), {"name": "", "subscription": "both"})["subscription"] = "both"
            return
        show = el.findtext(f"{{{NS['client']}}}show", default="")
        status = el.findtext(f"{{{NS['client']}}}status", default="")
        self.broadcast_presence(unavailable=(typ == "unavailable"), show=show, status=status)
        if typ != "unavailable":
            # Tell the newcomer who else is online.
            for s in list(STATE.sessions.values()):
                if s.user != self.user:
                    self.send(f"<presence from='{s.full}' to='{self.bare}'/>")

    # -- messages --
    def handle_message(self, el):
        to = el.get("to", "").lower()
        bare = to.split("/")[0]
        el.set("from", self.full)
        ET.register_namespace("", NS["client"])
        text = ET.tostring(el, encoding="unicode")
        delivered = False
        for s in list(STATE.sessions.values()):
            if s.bare == bare:
                s.send(text)
                delivered = True
        if not delivered:
            STATE.offline.setdefault(bare, []).append(text)
        body = el.findtext(f"{{{NS['client']}}}body", default="")
        enc = el.find("{eu.siacs.conversations.axolotl}encrypted")
        print(f"[msg] {self.full} -> {bare}: {'<OMEMO>' if enc is not None else body[:60]!r} ({'live' if delivered else 'offline'})")


class UploadHandler(BaseHTTPRequestHandler):
    def do_PUT(self):
        n = int(self.headers.get("Content-Length") or 0)
        STATE.files[self.path] = self.rfile.read(n)
        print(f"[http] PUT {self.path} {n} bytes")
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        data = STATE.files.get(self.path)
        if data is None:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        print(f"[http] GET {self.path} {len(data)} bytes")

    def log_message(self, *a):
        pass


def start_http(tls_ctx):
    plain = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), UploadHandler)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    secure = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT + 1), UploadHandler)
    secure.socket = tls_ctx.wrap_socket(secure.socket, server_side=True)
    threading.Thread(target=secure.serve_forever, daemon=True).start()
    print(f"[http] upload store on http://localhost:{HTTP_PORT} and https://localhost:{HTTP_PORT + 1}")


async def main():
    ensure_cert()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(CERT, KEY)
    start_http(tls)

    async def handle(reader, writer):
        await Session(reader, writer, tls).run()

    server = await asyncio.start_server(handle, "0.0.0.0", PORT)
    print(f"[xmpp] {DOMAIN} on port {PORT}; users: {', '.join(u + '@' + DOMAIN for u in USERS)} (any password)")
    print(f"[xmpp] point the app at host 127.0.0.1 (or add '{DOMAIN}' to the hosts file)")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
