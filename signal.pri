# The crypto primitives (plain C) and the Signal protocol layer, shared by the app and the
# desktop tests.
INCLUDEPATH += $$PWD/src

HEADERS += \
    $$PWD/src/crypto/xeddsa.h \
    $$PWD/src/crypto/sha256.h \
    $$PWD/src/crypto/aes.h \
    $$PWD/src/signal/curve.h \
    $$PWD/src/signal/protobuf.h \
    $$PWD/src/signal/messages.h \
    $$PWD/src/signal/ratchet.h \
    $$PWD/src/signal/state.h \
    $$PWD/src/signal/store.h \
    $$PWD/src/signal/session.h

SOURCES += \
    $$PWD/src/crypto/xeddsa.c \
    $$PWD/src/crypto/sha256.c \
    $$PWD/src/crypto/aes.c \
    $$PWD/src/signal/curve.cpp \
    $$PWD/src/signal/protobuf.cpp \
    $$PWD/src/signal/messages.cpp \
    $$PWD/src/signal/ratchet.cpp \
    $$PWD/src/signal/state.cpp \
    $$PWD/src/signal/store.cpp \
    $$PWD/src/signal/session.cpp

win32:LIBS += -ladvapi32
