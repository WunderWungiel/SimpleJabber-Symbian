// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
import QtQuick 1.1
import com.nokia.symbian 1.1

Page {
    id: page
    property variant chat: app.chat
    property variant contact: app.contacts.get(app.contacts.indexOf(chat.jid))
    property bool omemo: contact ? contact.omemo : false

    Component { id: imagePage; ImagePage {} }
    Component { id: textPage; TextInputPage {} }

    // The contact row changes (presence, OMEMO toggle): refresh the cached copy.
    Connections {
        target: app.contacts
        onCountChanged: contact = app.contacts.get(app.contacts.indexOf(chat.jid))
    }

    tools: ToolBarLayout {
        ToolButton { iconSource: "toolbar-back"; onClicked: pageStack.pop() }
        ToolButton {
            iconSource: "toolbar-add"
            enabled: app.connected && !app.busy
            onClicked: { var p = app.pickImage(); if (p != "") app.sendImageFile(p) }
        }
        ToolButton {
            text: omemo ? qsTr("OMEMO on") : qsTr("OMEMO off")
            onClicked: app.setChatOmemo(chat.jid, !omemo)
        }
        ToolButton { iconSource: "toolbar-menu"; onClicked: menu.open() }
    }

    Menu {
        id: menu
        MenuLayout {
            MenuItem { text: qsTr("Fingerprints"); onClicked: fingerprintDialog.open() }
            MenuItem { text: qsTr("Rename contact"); onClicked: pageStack.push(textPage, { title: qsTr("Rename contact"), hint: qsTr("name"), action: "rename", jid: chat.jid, initial: contact && contact.hasName ? contact.name : "" }) }
            MenuItem { text: qsTr("Clear history"); onClicked: app.clearHistory(chat.jid) }
        }
    }

    QueryDialog {
        id: fingerprintDialog
        titleText: qsTr("OMEMO fingerprints")
        message: qsTr("Yours (device %1):\n%2\n\n%3:\n%4")
                 .arg(app.ownDeviceId).arg(app.ownFingerprint != "" ? app.ownFingerprint : qsTr("not ready"))
                 .arg(contact ? contact.name : chat.jid)
                 .arg(app.contactFingerprint(chat.jid) != "" ? app.contactFingerprint(chat.jid) : qsTr("no OMEMO session yet"))
        acceptButtonText: qsTr("Close")
    }

    ContextMenu {
        id: contextMenu
        property variant item
        MenuLayout {
            MenuItem { text: qsTr("Copy text"); visible: contextMenu.item ? !contextMenu.item.isImage : false; onClicked: app.copyText(contextMenu.item.body) }
            MenuItem { text: qsTr("Open link"); visible: contextMenu.item ? contextMenu.item.hasUrl : false; onClicked: app.openUrl(contextMenu.item.url) }
        }
    }

    ListHeading {
        id: heading
        anchors { top: parent.top; left: parent.left; right: parent.right }
        Rectangle {
            id: dot
            anchors { left: heading.paddingItem.left; verticalCenter: parent.verticalCenter }
            width: 12; height: 12; radius: 6
            property int p: contact ? contact.presence : 5
            color: p == 0 || p == 1 ? "#5fcf5f" : (p == 2 || p == 3 ? "#e6c34a" : (p == 4 ? "#e05a5a" : "#666666"))
        }
        Padlock {
            id: headerLock
            anchors { right: heading.paddingItem.right; verticalCenter: parent.verticalCenter }
            visible: omemo
            size: platformStyle.fontSizeLarge
        }
        ListItemText {
            anchors { left: dot.right; leftMargin: platformStyle.paddingMedium
                      right: headerLock.visible ? headerLock.left : heading.paddingItem.right
                      rightMargin: platformStyle.paddingSmall; verticalCenter: parent.verticalCenter }
            role: "Heading"
            text: contact ? contact.name : chat.jid
            elide: Text.ElideRight
            horizontalAlignment: Text.AlignLeft
        }
    }

    ListView {
        id: list
        anchors { top: heading.bottom; left: parent.left; right: parent.right; bottom: composerRow.top }
        model: chat
        clip: true
        spacing: platformStyle.paddingSmall
        cacheBuffer: 600
        delegate: MessageDelegate {
            width: list.width
            onPressAndHold: { contextMenu.item = chat.get(index); contextMenu.open() }
            onImageClicked: pageStack.push(imagePage, { source: path })
            onLinkClicked: app.openUrl(url)
        }
        ScrollDecorator { flickableItem: list }
        function scrollToEnd() { if (count > 0) positionViewAtEnd() }
    }

    Connections {
        target: chat
        onJidChanged: list.scrollToEnd()
        onCountChanged: list.scrollToEnd()
    }
    Component.onCompleted: list.scrollToEnd()

    Label {
        anchors.centerIn: list
        width: parent.width - 2 * platformStyle.paddingLarge
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.Wrap
        color: platformStyle.colorNormalMid
        visible: list.count == 0
        text: qsTr("No messages yet.")
    }

    Item {
        id: composerRow
        anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
        height: composer.height + 2 * platformStyle.paddingSmall
        TextArea {
            id: composer
            anchors { left: parent.left; leftMargin: platformStyle.paddingSmall; right: sendButton.left; rightMargin: platformStyle.paddingSmall; verticalCenter: parent.verticalCenter }
            placeholderText: qsTr("message")
            wrapMode: TextEdit.Wrap
            platformMaxImplicitHeight: 120
        }
        Button {
            id: sendButton
            anchors { right: parent.right; rightMargin: platformStyle.paddingSmall; verticalCenter: parent.verticalCenter }
            width: 80
            text: qsTr("Send")
            enabled: composer.text.length > 0 && app.connected
            onClicked: { app.sendText(composer.text); composer.text = "" }
        }
    }
}
