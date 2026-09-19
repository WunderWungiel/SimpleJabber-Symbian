// SimpleJabber - an XMPP client with OMEMO for Symbian Belle.
// Copyright (C) 2026 Symnok - MIT License, see LICENSE.
//
// One message bubble: date separator, text or inline picture, time and a lock for OMEMO.
import QtQuick 1.1
import com.nokia.symbian 1.1

Item {
    id: root
    signal pressAndHold
    signal imageClicked(string path)
    signal linkClicked(string url)

    property int maxBubbleWidth: width * 0.8
    height: column.height + platformStyle.paddingSmall

    Column {
        id: column
        anchors { left: parent.left; right: parent.right }
        spacing: platformStyle.paddingSmall

        Item {
            width: parent.width
            height: model.showDate ? dateLabel.height + platformStyle.paddingMedium : 0
            visible: model.showDate
            Label { id: dateLabel; anchors.centerIn: parent; text: model.dateText; font.pixelSize: platformStyle.fontSizeSmall; color: platformStyle.colorNormalMid }
        }

        Rectangle {
            id: bubble
            property real innerWidth: Math.max(model.isImage ? contentColumn.width : 0, model.isImage ? 0 : bodyLabel.paintedWidth, timeRow.width)
            width: Math.min(maxBubbleWidth, innerWidth + 2 * platformStyle.paddingMedium)
            height: contentColumn.height + timeRow.height + 2 * platformStyle.paddingMedium + platformStyle.paddingSmall
            radius: 8
            color: model.failed ? "#6b2b2b" : (model.outgoing ? "#1f5e8a" : "#3a3a3a")
            opacity: model.pending ? 0.6 : 1
            anchors { right: model.outgoing ? parent.right : undefined; left: model.outgoing ? undefined : parent.left; margins: platformStyle.paddingMedium }

            MouseArea {
                anchors.fill: parent
                onPressAndHold: root.pressAndHold()
                onClicked: if (model.hasUrl && !model.isImage) root.linkClicked(model.url)
            }

            Column {
                id: contentColumn
                anchors { left: parent.left; top: parent.top; margins: platformStyle.paddingMedium }
                width: maxBubbleWidth - 2 * platformStyle.paddingMedium
                spacing: platformStyle.paddingSmall

                Item {
                    visible: model.isImage
                    width: parent.width
                    height: model.isImage ? (photo.status == Image.Ready ? photo.height : 100) : 0
                    Rectangle {
                        anchors.fill: parent; color: "#222222"; radius: 4
                        visible: photo.status != Image.Ready
                        Label {
                            anchors.centerIn: parent
                            text: model.imagePath == "" ? qsTr("loading picture...") : (photo.status == Image.Error ? qsTr("picture unavailable") : qsTr("loading..."))
                            font.pixelSize: platformStyle.fontSizeSmall; color: platformStyle.colorNormalMid
                        }
                    }
                    Image {
                        id: photo
                        width: parent.width
                        source: model.imagePath
                        asynchronous: true
                        smooth: true
                        fillMode: Image.PreserveAspectFit
                        sourceSize.width: parent.width
                        visible: status == Image.Ready
                    }
                    MouseArea {
                        anchors.fill: parent
                        onClicked: if (photo.status == Image.Ready) root.imageClicked(model.imagePath)
                        onPressAndHold: root.pressAndHold()
                    }
                }

                Label {
                    id: bodyLabel
                    visible: !model.isImage
                    width: parent.width
                    text: model.body
                    wrapMode: Text.Wrap
                    color: model.hasUrl ? platformStyle.colorNormalLink : "white"
                }
            }

            Row {
                id: timeRow
                anchors { right: parent.right; bottom: parent.bottom; margins: platformStyle.paddingSmall }
                spacing: platformStyle.paddingSmall
                Padlock { visible: model.encrypted; size: platformStyle.fontSizeSmall; anchors.verticalCenter: parent.verticalCenter }
                Label { text: model.timeText; font.pixelSize: platformStyle.fontSizeSmall * 0.85; color: "#c0c0c0" }
                Label { visible: model.outgoing; text: model.failed ? "!" : (model.pending ? "..." : ""); font.pixelSize: platformStyle.fontSizeSmall * 0.85; color: model.failed ? "#ff9b9b" : "#c0c0c0" }
            }
        }
    }
}
