// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// A one-field page (the components have no input dialog): add a contact, rename one.
import QtQuick 1.1
import com.nokia.symbian 1.1

Page {
    id: page
    property string title
    property string hint
    property string action     // "add" | "rename"
    property string jid
    property string initial

    tools: ToolBarLayout {
        ToolButton { iconSource: "toolbar-back"; onClicked: pageStack.pop() }
    }

    ListHeading {
        id: heading
        anchors { top: parent.top; left: parent.left; right: parent.right }
        ListItemText { anchors.fill: heading.paddingItem; role: "Heading"; text: title }
    }

    Column {
        anchors { top: heading.bottom; left: parent.left; right: parent.right; margins: platformStyle.paddingLarge }
        spacing: platformStyle.paddingMedium
        TextField {
            id: field
            width: parent.width
            text: initial
            placeholderText: hint
            inputMethodHints: action == "add" ? (Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText | Qt.ImhEmailCharactersOnly) : Qt.ImhNone
            Keys.onReturnPressed: page.accept()
        }
        Button {
            width: parent.width
            text: qsTr("OK")
            onClicked: page.accept()
        }
    }

    function accept() {
        field.closeSoftwareInputPanel()
        if (action == "add") app.addContact(field.text)
        else if (action == "rename") app.renameContact(jid, field.text)
        pageStack.pop()
    }

    onStatusChanged: if (status == PageStatus.Active) field.forceActiveFocus()
}
