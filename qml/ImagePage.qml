// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
import QtQuick 1.1
import com.nokia.symbian 1.1

Page {
    id: page
    property string source

    tools: ToolBarLayout {
        ToolButton { iconSource: "toolbar-back"; onClicked: pageStack.pop() }
    }

    Rectangle { anchors.fill: parent; color: "black" }

    Flickable {
        id: flick
        anchors.fill: parent
        contentWidth: Math.max(width, image.width * image.scale)
        contentHeight: Math.max(height, image.height * image.scale)
        clip: true
        Image {
            id: image
            source: page.source
            asynchronous: true
            smooth: true
            fillMode: Image.PreserveAspectFit
            width: flick.width
            height: flick.height
            transformOrigin: Item.TopLeft
            property bool zoomed: false
            scale: zoomed ? 2 : 1
            x: zoomed ? 0 : (flick.width - width) / 2
            y: zoomed ? 0 : (flick.height - height) / 2
            MouseArea { anchors.fill: parent; onDoubleClicked: image.zoomed = !image.zoomed }
        }
    }
    BusyIndicator { anchors.centerIn: parent; running: image.status == Image.Loading; visible: running; width: platformStyle.graphicSizeLarge; height: platformStyle.graphicSizeLarge }
}
