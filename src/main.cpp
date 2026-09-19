// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
#include "app/appcontroller.h"
#include "app/contactsmodel.h"
#include "app/messagesmodel.h"
#include "app/networkmanager.h"
#include "crypto/xeddsa.h"
#include "signal/curve.h"

#include <QApplication>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <cstdio>
#include <cstdlib>
#ifdef Q_OS_WIN
#include <windows.h>
#endif
#include <QDeclarativeContext>
#include <QDeclarativeEngine>
#include <QDeclarativeNetworkAccessManagerFactory>
#include <QDeclarativeView>
#include <QSettings>
#include <QTranslator>
#include <QUrl>
#include <QtDeclarative>

namespace {

/// Warnings and QML errors go to <data dir>/simplejabber.log (capped at ~200 KB) as well as
/// to the debugger: on the phone that file is the only way to see what went wrong.
QFile *g_log = 0;

void logHandler(QtMsgType type, const char *msg)
{
    if (g_log && g_log->isOpen()) {
        if (g_log->size() > 200 * 1024) { g_log->resize(0); }
        const char *tag = type == QtDebugMsg ? "D" : type == QtWarningMsg ? "W" : type == QtCriticalMsg ? "C" : "F";
        g_log->write(QDateTime::currentDateTime().toString(QLatin1String("MM-dd HH:mm:ss ")).toLatin1());
        g_log->write(tag, 1);
        g_log->write(" ", 1);
        g_log->write(msg);
        g_log->write("\n", 1);
        g_log->flush();
    }
#ifdef Q_OS_WIN
    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
#else
    fprintf(stderr, "%s\n", msg);
#endif
    if (type == QtFatalMsg) abort();
}

/// QML Image elements load through their own access manager (on a separate thread), so
/// they get the same trust roots as everything else.
class NetworkFactory : public QDeclarativeNetworkAccessManagerFactory
{
public:
    QNetworkAccessManager *create(QObject *parent) { return new NetworkManager(parent); }
};

void naclRandom(unsigned char *out, unsigned long long len)
{
    const QByteArray b = Signal::Curve::randomBytes(int(len));
    memcpy(out, b.constData(), size_t(len));
}

}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName(QLatin1String("SimpleJabber"));
    app.setOrganizationName(QLatin1String("SimpleJabber"));

    nacl_set_random_source(naclRandom);

    QString logDir = QDesktopServices::storageLocation(QDesktopServices::DataLocation);
    if (logDir.isEmpty()) logDir = QDir::homePath();
    QDir().mkpath(logDir);
    g_log = new QFile(logDir + QLatin1String("/simplejabber.log"));
    g_log->open(QIODevice::WriteOnly | QIODevice::Append);
    qInstallMsgHandler(logHandler);
    qWarning("SimpleJabber starting");

    QSettings settings(QLatin1String("SimpleJabber"), QLatin1String("SimpleJabber"));
    const QString lang = AppController::effectiveLanguage(settings);
    QTranslator translator;
    if (lang != QLatin1String("en") && translator.load(QLatin1String(":/translations/simplejabber_") + lang))
        app.installTranslator(&translator);

    qmlRegisterType<ContactsModel>();
    qmlRegisterType<MessagesModel>();

    AppController controller;
    NetworkFactory factory;

    QDeclarativeView view;
    view.engine()->setNetworkAccessManagerFactory(&factory);
    view.setResizeMode(QDeclarativeView::SizeRootObjectToView);
    view.rootContext()->setContextProperty(QLatin1String("app"), &controller);
    controller.setView(&view);
    view.setSource(QUrl(QLatin1String("qrc:/qml/main.qml")));

#if defined(Q_OS_SYMBIAN) || defined(Q_WS_SIMULATOR)
    view.setAttribute(Qt::WA_LockPortraitOrientation, true);
    view.showFullScreen();
#else
    view.resize(360, 640);
    view.show();
#endif

    controller.start();
    return app.exec();
}
