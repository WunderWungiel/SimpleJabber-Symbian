// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
import QtQuick 1.1
import com.nokia.symbian 1.1

Page {
    id: page
    // When opened from the contact list as "Account", editing an existing account.
    property bool editing: false

    tools: ToolBarLayout {
        ToolButton { iconSource: "toolbar-back"; onClicked: editing ? pageStack.pop() : Qt.quit() }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: column.height + 2 * platformStyle.paddingLarge
        flickableDirection: Flickable.VerticalFlick
        clip: true

        Column {
            id: column
            anchors { left: parent.left; right: parent.right; top: parent.top; margins: platformStyle.paddingLarge }
            spacing: platformStyle.paddingMedium

            Label { text: "SimpleJabber"; font.pixelSize: platformStyle.fontSizeLarge * 1.5; anchors.horizontalCenter: parent.horizontalCenter }
            Label { text: editing ? qsTr("account") : qsTr("sign in to your XMPP account"); color: platformStyle.colorNormalMid; anchors.horizontalCenter: parent.horizontalCenter }
            Item { width: 1; height: platformStyle.paddingLarge }

            Label { text: qsTr("Jabber ID"); font.pixelSize: platformStyle.fontSizeSmall }
            TextField {
                id: jidField
                width: parent.width
                text: app.accountJid
                placeholderText: "user@example.com"
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhEmailCharactersOnly
                enabled: !app.busy
            }
            Label { text: qsTr("password"); font.pixelSize: platformStyle.fontSizeSmall }
            TextField {
                id: passwordField
                width: parent.width
                text: app.accountPassword
                echoMode: TextInput.Password
                inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                placeholderText: qsTr("password")
            }

            Item { width: 1; height: platformStyle.paddingSmall }
            ListItem {
                id: advancedItem
                ListItemText { anchors { left: advancedItem.paddingItem.left; verticalCenter: parent.verticalCenter }
                    role: "Title"; text: qsTr("Advanced") }
                Label {
                    anchors { right: advancedItem.paddingItem.right; verticalCenter: parent.verticalCenter }
                    text: advanced.visible ? "-" : "+"
                    font.pixelSize: platformStyle.fontSizeLarge
                }
                onClicked: advanced.visible = !advanced.visible
            }
            Column {
                id: advanced
                width: parent.width
                spacing: platformStyle.paddingMedium
                visible: app.accountHost != "" || app.accountPort != 5222
                Label { text: qsTr("server (leave empty to use the JID's domain)"); font.pixelSize: platformStyle.fontSizeSmall; width: parent.width; wrapMode: Text.Wrap }
                TextField {
                    id: hostField
                    width: parent.width
                    text: app.accountHost
                    placeholderText: qsTr("server host")
                    inputMethodHints: Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhUrlCharactersOnly
                }
                Label { text: qsTr("port"); font.pixelSize: platformStyle.fontSizeSmall }
                TextField {
                    id: portField
                    width: parent.width
                    text: app.accountPort
                    inputMethodHints: Qt.ImhDigitsOnly
                    validator: IntValidator { bottom: 1; top: 65535 }
                }
            }

            Item { width: 1; height: platformStyle.paddingMedium }
            Button {
                text: editing ? qsTr("Save and reconnect") : qsTr("Sign in")
                width: parent.width
                enabled: !app.busy
                onClicked: {
                    passwordField.closeSoftwareInputPanel()
                    if (editing) {
                        app.disconnectNow()
                        app.saveAccount(jidField.text, passwordField.text, hostField.text, parseInt(portField.text))
                        app.connectNow()
                        pageStack.pop()
                    } else {
                        app.signIn(jidField.text, passwordField.text, hostField.text, parseInt(portField.text))
                    }
                }
            }

            Item { width: 1; height: platformStyle.paddingLarge }
            Label {
                width: parent.width
                wrapMode: Text.Wrap
                font.pixelSize: platformStyle.fontSizeSmall
                color: platformStyle.colorNormalMid
                text: app.sslSupported
                      ? qsTr("The connection is protected with TLS. OMEMO end-to-end encryption can be turned on per contact in the chat.")
                      : qsTr("This Qt build has no TLS support - install the Qt TLS patch (nnproject.cc/qtls) first.")
            }
        }
    }
}
