// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
import QtQuick 1.1
import com.nokia.symbian 1.1
import com.nokia.extras 1.1

PageStackWindow {
    id: window
    showStatusBar: true
    showToolBar: true
    platformSoftwareInputPanelEnabled: true
    initialPage: startPage

    Page {
        id: startPage
        BusyIndicator { anchors.centerIn: parent; running: true; width: platformStyle.graphicSizeLarge; height: platformStyle.graphicSizeLarge }
        tools: ToolBarLayout { ToolButton { iconSource: "toolbar-back"; onClicked: Qt.quit() } }
    }

    Component { id: loginPage; LoginPage {} }
    Component { id: contactsPage; ContactsPage {} }

    property bool routed: false

    function route() {
        if (app.state == "login") {
            pageStack.clear()
            pageStack.push(loginPage)
            routed = false
        } else if (!routed) {
            pageStack.clear()
            pageStack.push(contactsPage)
            routed = true
        }
    }

    Connections {
        target: app
        onStateChanged: route()
        onNoticeChanged: if (app.notice != "") { banner.text = app.notice; banner.open() }
        onCertChanged: if (app.certPrompt) certDialog.open()
    }

    Component.onCompleted: route()

    InfoBanner { id: banner; timeout: 4000; onClicked: app.clearNotice() }

    QueryDialog {
        id: certDialog
        titleText: qsTr("Untrusted certificate")
        message: qsTr("The certificate of %1 could not be verified (%2).\n\nSubject: %3\nSHA-256: %4\n\nTrust this certificate for this server?")
                 .arg(app.certHost).arg(app.certErrors).arg(app.certSubject).arg(app.certFingerprint)
        acceptButtonText: qsTr("Trust")
        rejectButtonText: qsTr("Cancel")
        onAccepted: app.acceptCertificate()
        onRejected: app.dismissCertificate()
    }
}
