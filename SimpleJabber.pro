# SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
# Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#
# Build with the "Qt 4.7.4 for Symbian Anna/Belle" kit for the phone (build-symbian.cmd),
# or with the Qt Simulator kit to run it on the PC.

TEMPLATE = app
TARGET = SimpleJabber
VERSION = 1.0.5

QT += core gui network declarative

include(signal.pri)
include(xmpp.pri)

INCLUDEPATH += src src/app src/xmpp src/omemo

HEADERS += \
    src/app/networkmanager.h \
    src/app/messagestore.h \
    src/app/mediacache.h \
    src/app/imageuploader.h \
    src/app/contactsmodel.h \
    src/app/messagesmodel.h \
    src/app/appcontroller.h

SOURCES += \
    src/main.cpp \
    src/app/networkmanager.cpp \
    src/app/messagestore.cpp \
    src/app/mediacache.cpp \
    src/app/imageuploader.cpp \
    src/app/contactsmodel.cpp \
    src/app/messagesmodel.cpp \
    src/app/appcontroller.cpp

RESOURCES += qml.qrc translations.qrc

DEFINES += APP_VERSION=$$VERSION
CODECFORTR = UTF-8
CODECFORSRC = UTF-8

TRANSLATIONS += translations/simplejabber_ru.ts

OTHER_FILES += qml/*.qml README.md

symbian {
    TARGET.UID3 = 0xE31A0C4C
    TARGET.CAPABILITY += NetworkServices ReadUserData WriteUserData
    # Curve25519 and the picture codecs want room: 128 MB max heap, 80 KB stack (TweetNaCl
    # keeps its field elements on the stack).
    TARGET.EPOCHEAPSIZE = 0x020000 0x8000000
    TARGET.EPOCSTACKSIZE = 0x14000
    ICON = icon.svg

    CONFIG += qt-components
    DEPLOYMENT.installer_header = 0x2002CCCF

    vendorinfo = \
        "; Localised and unique vendor names" \
        "%{\"Symnok\"}" \
        ":\"Symnok\""
    # Symbian wants the version comma-separated (1,0,2); derive it from VERSION so the
    # installer shows the same number that bump-version.py wrote (was hardcoded 1,0,0).
    VERSION_COMMA = $$replace(VERSION, "\\.", ",")
    packageheader = "$${LITERAL_HASH}{\"SimpleJabber\"},(0xE31A0C4C),$${VERSION_COMMA},TYPE=SA,RU"
    deployment.pkg_prerules += packageheader vendorinfo
    DEPLOYMENT += deployment
}

simulator {
    DEFINES += Q_WS_SIMULATOR
}
