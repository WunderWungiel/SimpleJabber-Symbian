// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// A small green padlock for OMEMO-encrypted chats, drawn with rectangles (QtQuick 1.1 has
// no Canvas/Shape, and a Unicode lock glyph does not render in the Symbian fonts).
import QtQuick 1.1

Item {
    id: root
    property color color: "#3fbf3f"
    property int size: 16
    width: size
    height: size

    // Shackle: an open-bottomed rounded rectangle; its lower half is hidden by the body.
    Rectangle {
        anchors.horizontalCenter: parent.horizontalCenter
        y: 0
        width: root.size * 0.55
        height: root.size * 0.62
        radius: width / 2
        color: "transparent"
        border.color: root.color
        border.width: Math.max(2, root.size * 0.12)
    }
    // Body.
    Rectangle {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        width: root.size
        height: root.size * 0.6
        radius: Math.max(1, root.size * 0.12)
        color: root.color
    }
}
