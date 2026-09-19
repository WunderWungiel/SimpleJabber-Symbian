// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
import QtQuick 1.1
import com.nokia.symbian 1.1

Page {
    id: page

    Component { id: chatPage; ChatPage {} }
    Component { id: settingsPage; SettingsPage {} }
    Component { id: accountPage; LoginPage { editing: true } }
    Component { id: textPage; TextInputPage {} }

    tools: ToolBarLayout {
        ToolButton { iconSource: "toolbar-back"; onClicked: Qt.quit() }
        ToolButton {
            iconSource: "toolbar-add"
            enabled: app.connected
            onClicked: pageStack.push(textPage, { title: qsTr("Add contact"), hint: "user@example.com", action: "add" })
        }
        ToolButton {
            iconSource: "toolbar-refresh"
            enabled: app.state != "connecting"
            onClicked: { if (app.connected) app.disconnectNow(); app.connectNow() }
        }
        ToolButton { iconSource: "toolbar-menu"; onClicked: menu.open() }
    }

    Menu {
        id: menu
        MenuLayout {
            MenuItem { text: app.connected ? qsTr("Go offline") : qsTr("Connect"); onClicked: app.connected ? app.disconnectNow() : app.connectNow() }
            MenuItem { text: qsTr("Account"); onClicked: pageStack.push(accountPage) }
            MenuItem { text: qsTr("Settings"); onClicked: pageStack.push(settingsPage) }
            MenuItem { text: qsTr("Sign out"); onClicked: signOutDialog.open() }
        }
    }

    QueryDialog {
        id: signOutDialog
        titleText: qsTr("Sign out")
        message: qsTr("Sign out? The account and password are removed from this phone. Message history and OMEMO keys stay until you sign in again.")
        acceptButtonText: qsTr("Sign out")
        rejectButtonText: qsTr("Cancel")
        onAccepted: app.signOut()
    }

    ContextMenu {
        id: contextMenu
        property variant item
        MenuLayout {
            MenuItem {
                text: qsTr("Rename")
                onClicked: pageStack.push(textPage, { title: qsTr("Rename contact"), hint: qsTr("name"), action: "rename", jid: contextMenu.item.jid, initial: contextMenu.item.hasName ? contextMenu.item.name : "" })
            }
            MenuItem {
                text: contextMenu.item && contextMenu.item.omemo ? qsTr("Turn OMEMO off") : qsTr("Turn OMEMO on")
                onClicked: app.setChatOmemo(contextMenu.item.jid, !contextMenu.item.omemo)
            }
            MenuItem { text: qsTr("Clear history"); onClicked: app.clearHistory(contextMenu.item.jid) }
            MenuItem { text: qsTr("Remove contact"); onClicked: { removeDialog.jid = contextMenu.item.jid; removeDialog.name = contextMenu.item.name; removeDialog.open() } }
        }
    }

    QueryDialog {
        id: removeDialog
        property string jid
        property string name
        titleText: qsTr("Remove contact")
        message: qsTr("Remove %1 from the contact list and delete the conversation?").arg(name)
        acceptButtonText: qsTr("Remove")
        rejectButtonText: qsTr("Cancel")
        onAccepted: app.removeContact(jid)
    }

    ListHeading {
        id: heading
        anchors { top: parent.top; left: parent.left; right: parent.right }
        ListItemText { anchors.fill: heading.paddingItem; role: "Heading"; text: app.stateText != "" ? app.stateText : qsTr("Contacts"); elide: Text.ElideRight }
        BusyIndicator {
            anchors { right: heading.paddingItem.right; verticalCenter: parent.verticalCenter }
            running: app.state == "connecting" || app.busy
            visible: running
        }
    }

    ListView {
        id: list
        anchors { top: heading.bottom; left: parent.left; right: parent.right; bottom: parent.bottom }
        model: app.contacts
        clip: true

        header: Column {
            width: list.width
            Repeater {
                model: app.requests
                delegate: Rectangle {
                    width: list.width
                    height: reqColumn.height + 2 * platformStyle.paddingMedium
                    color: "#2a3d55"
                    Column {
                        id: reqColumn
                        anchors { left: parent.left; right: parent.right; top: parent.top; margins: platformStyle.paddingMedium }
                        spacing: platformStyle.paddingSmall
                        Label { width: parent.width; wrapMode: Text.Wrap; text: qsTr("%1 wants to see when you are online.").arg(modelData); font.pixelSize: platformStyle.fontSizeSmall }
                        Row {
                            spacing: platformStyle.paddingMedium
                            Button { text: qsTr("Accept"); width: 120; onClicked: app.acceptRequest(modelData) }
                            Button { text: qsTr("Decline"); width: 120; onClicked: app.declineRequest(modelData) }
                        }
                    }
                }
            }
        }

        delegate: ListItem {
            id: item
            Rectangle {
                id: dot
                anchors { left: item.paddingItem.left; verticalCenter: parent.verticalCenter }
                width: 14; height: 14; radius: 7
                color: model.presence == 0 || model.presence == 1 ? "#5fcf5f"
                     : (model.presence == 2 || model.presence == 3 ? "#e6c34a" : (model.presence == 4 ? "#e05a5a" : "#666666"))
            }
            Column {
                anchors { left: dot.right; leftMargin: platformStyle.paddingMedium; right: rightColumn.left; rightMargin: platformStyle.paddingSmall; verticalCenter: parent.verticalCenter }
                ListItemText { width: parent.width; role: "Title"; text: model.name; elide: Text.ElideRight }
                ListItemText {
                    width: parent.width; role: "SubTitle"; elide: Text.ElideRight
                    text: model.lastMessage != "" ? model.lastMessage.replace(/\n/g, " ") : model.presenceText
                    color: model.unread > 0 ? platformStyle.colorNormalLight : platformStyle.colorNormalMid
                }
            }
            Column {
                id: rightColumn
                anchors { right: item.paddingItem.right; verticalCenter: parent.verticalCenter }
                spacing: platformStyle.paddingSmall
                Padlock { anchors.right: parent.right; visible: model.omemo; size: platformStyle.fontSizeMedium }
                Rectangle {
                    anchors.right: parent.right
                    width: Math.max(badge.width + 12, 24); height: 24; radius: 12
                    color: "#e8722a"
                    visible: model.unread > 0
                    Label { id: badge; anchors.centerIn: parent; text: model.unread; font.pixelSize: platformStyle.fontSizeSmall; color: "white" }
                }
            }
            onClicked: { app.openChat(model.jid); pageStack.push(chatPage) }
            onPressAndHold: { contextMenu.item = app.contacts.get(index); contextMenu.open() }
        }
        ScrollDecorator { flickableItem: list }
    }

    Label {
        anchors.centerIn: list
        width: parent.width - 2 * platformStyle.paddingLarge
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.Wrap
        color: platformStyle.colorNormalMid
        visible: list.count == 0 && app.requests.length == 0
        text: app.connected ? qsTr("No contacts yet. Tap + to add one.") : app.stateText
    }

    onStatusChanged: if (status == PageStatus.Active) app.closeChat()
}
