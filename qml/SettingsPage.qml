// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
import QtQuick 1.1
import com.nokia.symbian 1.1

Page {
    id: page

    tools: ToolBarLayout {
        ToolButton { iconSource: "toolbar-back"; onClicked: pageStack.pop() }
    }

    SelectionDialog {
        id: languageDialog
        titleText: qsTr("App language")
        model: ListModel {
            ListElement { name: "System default"; code: "" }
            ListElement { name: "English"; code: "en" }
            ListElement { name: "Русский"; code: "ru" }
        }
        delegate: Item {
            width: parent ? parent.width : 300
            height: (typeof privateStyle != "undefined") ? privateStyle.menuItemHeight : 56
            Rectangle { anchors.fill: parent; color: rowMouse.pressed ? "#3d5a80" : "transparent" }
            Label {
                anchors { left: parent.left; leftMargin: platformStyle.paddingLarge; right: parent.right; verticalCenter: parent.verticalCenter }
                text: (index == 0 ? qsTr("System default") : model.name) + (model.code == app.language ? "   *" : "")
                color: "white"
            }
            MouseArea { id: rowMouse; anchors.fill: parent; onClicked: { languageDialog.selectedIndex = index; languageDialog.accept() } }
        }
        onAccepted: if (selectedIndex >= 0) app.language = model.get(selectedIndex).code
    }

    QueryDialog {
        id: signOutDialog
        titleText: qsTr("Sign out")
        message: qsTr("Sign out? The account and password are removed from this phone. Message history and OMEMO keys stay until you sign in again.")
        acceptButtonText: qsTr("Sign out")
        rejectButtonText: qsTr("Cancel")
        onAccepted: app.signOut()
    }

    function languageName() {
        for (var i = 0; i < languageDialog.model.count; ++i)
            if (languageDialog.model.get(i).code == app.language) return i == 0 ? qsTr("System default") : languageDialog.model.get(i).name
        return qsTr("System default")
    }

    ListHeading {
        id: heading
        anchors { top: parent.top; left: parent.left; right: parent.right }
        ListItemText { anchors.fill: heading.paddingItem; role: "Heading"; text: qsTr("Settings") }
    }

    Flickable {
        anchors { top: heading.bottom; left: parent.left; right: parent.right; bottom: parent.bottom }
        contentHeight: column.height + platformStyle.paddingLarge
        clip: true
        Column {
            id: column
            width: parent.width

            ListItem {
                id: languageItem
                subItemIndicator: true
                Column {
                    anchors { left: languageItem.paddingItem.left; right: languageItem.paddingItem.right; verticalCenter: parent.verticalCenter }
                    ListItemText { width: parent.width; role: "Title"; text: qsTr("App language") }
                    Label { width: parent.width; text: languageName(); color: "white"; font.pixelSize: platformStyle.fontSizeSmall }
                }
                onClicked: languageDialog.open()
            }

            Item { width: 1; height: platformStyle.paddingLarge }
            Column {
                width: parent.width - 2 * platformStyle.paddingLarge
                x: platformStyle.paddingLarge
                spacing: platformStyle.paddingSmall
                Label { text: qsTr("OMEMO"); font.pixelSize: platformStyle.fontSizeLarge }
                Label { width: parent.width; wrapMode: Text.Wrap; font.pixelSize: platformStyle.fontSizeSmall; color: platformStyle.colorNormalMid
                        text: app.omemoReady ? qsTr("Ready. Device id %1.").arg(app.ownDeviceId) : qsTr("Not ready (connect first).") }
                Label { text: qsTr("Your fingerprint:"); font.pixelSize: platformStyle.fontSizeSmall }
                Label { width: parent.width; wrapMode: Text.WrapAnywhere; text: app.ownFingerprint != "" ? app.ownFingerprint : "-"; font.family: "Monospace"; font.pixelSize: platformStyle.fontSizeSmall; color: "white" }
                Button { text: qsTr("Copy fingerprint"); visible: app.ownFingerprint != ""; onClicked: app.copyText(app.ownFingerprint) }
            }

            Item { width: 1; height: platformStyle.paddingLarge }
            Column {
                width: parent.width - 2 * platformStyle.paddingLarge
                x: platformStyle.paddingLarge
                spacing: platformStyle.paddingSmall
                Label { text: qsTr("About"); font.pixelSize: platformStyle.fontSizeLarge }
                Label { width: parent.width; wrapMode: Text.Wrap; text: qsTr("SimpleJabber %1 - an XMPP client with OMEMO for Symbian Belle.").arg(app.version) }
                Label { width: parent.width; wrapMode: Text.Wrap; font.pixelSize: platformStyle.fontSizeSmall; color: platformStyle.colorNormalMid
                        text: app.sslSupported ? qsTr("TLS: OK (patched QtNetwork).") : qsTr("TLS: NOT available - install the Qt TLS patch from nnproject.cc/qtls.") }
                Label { width: parent.width; wrapMode: Text.Wrap; font.pixelSize: platformStyle.fontSizeSmall; color: platformStyle.colorNormalMid
                        text: qsTr("Derived from JabberWP (Windows Phone 8.1). MIT License. Crypto: TweetNaCl (public domain).") }
            }

            Item { width: 1; height: platformStyle.paddingLarge }
            ListItem {
                id: signOutItem
                ListItemText { anchors.fill: signOutItem.paddingItem; role: "Title"; text: qsTr("Sign out") }
                onClicked: signOutDialog.open()
            }
            ListItem {
                id: exitItem
                ListItemText { anchors.fill: exitItem.paddingItem; role: "Title"; text: qsTr("Exit") }
                onClicked: Qt.quit()
            }
        }
    }
}
