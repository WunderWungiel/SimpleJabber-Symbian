# The XMPP and OMEMO layers (on top of signal.pri), shared by the app and the tests.
INCLUDEPATH += $$PWD/src
HEADERS += $$PWD/src/xmpp/xmlelement.h $$PWD/src/xmpp/xmppstream.h $$PWD/src/xmpp/xmppclient.h $$PWD/src/omemo/omemomanager.h
SOURCES += $$PWD/src/xmpp/xmlelement.cpp $$PWD/src/xmpp/xmppstream.cpp $$PWD/src/xmpp/xmppclient.cpp $$PWD/src/omemo/omemomanager.cpp
RESOURCES += $$PWD/certs.qrc
