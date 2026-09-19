TEMPLATE = app
TARGET = xmpp_test
CONFIG += console
CONFIG -= app_bundle
QT -= gui
QT += network
include(../../signal.pri)
include(../../xmpp.pri)
SOURCES += main.cpp
