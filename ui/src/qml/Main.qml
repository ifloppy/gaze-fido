import QtQuick
import QtQuick.Controls as Controls
import QtQuick.Layouts
import QtQuick.Window
import QtCore
import Qt.labs.platform as Platform
import org.kde.kirigami as Kirigami
import org.gazefido.companion

Controls.ApplicationWindow {
    id: root
    objectName: "gazeFidoManagerWindow"

    width: 760
    height: 620
    minimumWidth: 560
    minimumHeight: 440
    visible: false
    title: "Gaze FIDO"
    property bool quitting: false

    Settings {
        id: appSettings
        category: "General"
        property bool showTrayIcon: true
    }

    property var credentials: parseCredentials(backend.credentials_json)
    property var sites: groupCredentials(credentials)
    property var activePrompt: ({})
    property string activeRequestId: ""
    property string promptResult: ""
    property bool promptBusy: false

    Backend {
        id: backend
        Component.onCompleted: start()
    }

    Platform.SystemTrayIcon {
        id: trayIcon
        visible: appSettings.showTrayIcon
        icon.name: "security-high"
        tooltip: "Gaze FIDO"
        menu: Platform.Menu {
            Platform.MenuItem {
                text: "显示 Gaze FIDO"
                icon.name: "window"
                onTriggered: root.showManager()
            }
            Platform.MenuItem {
                text: "退出 Gaze FIDO"
                icon.name: "application-exit"
                onTriggered: root.quitApplication()
            }
        }

        onActivated: function(reason) {
            if (reason === Platform.SystemTrayIcon.Trigger
                    || reason === Platform.SystemTrayIcon.DoubleClick)
                root.showManager()
        }
    }

    Timer {
        interval: 500
        repeat: false
        running: true
        onTriggered: {
            if (appSettings.showTrayIcon && !trayIcon.available)
                root.showManager()
        }
    }

    onClosing: function(close) {
        if (root.quitting)
            return
        close.accepted = false
        root.hide()
    }

    function parseCredentials(serialized) {
        try {
            const value = JSON.parse(serialized || "[]")
            return Array.isArray(value) ? value : []
        } catch (error) {
            return []
        }
    }

    function groupCredentials(records) {
        const groups = Object.create(null)
        for (const credential of records) {
            const rpId = credential.rp_id || "unknown"
            if (!groups[rpId]) {
                groups[rpId] = {
                    rpId: rpId,
                    name: credential.rp_name || rpId,
                    credentials: []
                }
            }
            groups[rpId].credentials.push(credential)
        }
        return Object.keys(groups).sort().map(key => groups[key])
    }

    function formatCreated(seconds) {
        const date = new Date(Number(seconds) * 1000)
        return Number.isNaN(date.getTime())
                ? "创建时间未知"
                : Qt.formatDateTime(date, "yyyy-MM-dd hh:mm")
    }

    function openVerificationPrompt(serialized) {
        try {
            // A previous successful prompt may still have its auto-close timer
            // pending. Do not let that timer close and cancel this new request.
            closePromptTimer.stop()
            activePrompt = JSON.parse(serialized)
            activeRequestId = activePrompt.request_id || ""
            promptResult = ""
            promptBusy = true
            verificationWindow.cancelPending = false
            verificationWindow.show()
            verificationWindow.raise()
            verificationWindow.requestActivate()
        } catch (error) {
            // Ignore malformed local control messages.
        }
    }

    function showManager() {
        root.show()
        root.raise()
        root.requestActivate()
    }

    function quitApplication() {
        root.quitting = true
        Qt.quit()
    }

    function cancelVerification() {
        if (!promptBusy || verificationWindow.cancelPending)
            return
        verificationWindow.cancelPending = true
        backend.cancelPrompt(activeRequestId)
    }

    function finishVerification(serialized) {
        try {
            const result = JSON.parse(serialized)
            if (result.request_id !== activeRequestId)
                return
            promptBusy = false
            switch (result.result) {
            case "verified":
                promptResult = "人脸验证通过，正在完成安全密钥操作。"
                break
            case "rejected":
                promptResult = "Gaze 未确认人脸匹配。"
                break
            case "cancelled":
                promptResult = "此次操作已取消。"
                break
            case "timeout":
                promptResult = "验证超时，请返回浏览器重新发起操作。"
                break
            default:
                promptResult = "Gaze 验证服务未能完成此次请求。"
            }
            closePromptTimer.restart()
        } catch (error) {
            // Ignore malformed local control messages.
        }
    }

    header: Controls.ToolBar {
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 18
            anchors.rightMargin: 12
            spacing: 12

            Kirigami.Icon {
                source: "security-high"
                implicitWidth: 30
                implicitHeight: 30
                Layout.alignment: Qt.AlignVCenter
            }

            ColumnLayout {
                spacing: 1
                Controls.Label {
                    text: "Gaze FIDO"
                    font.pointSize: 17
                    font.weight: Font.DemiBold
                }
                Controls.Label {
                    text: "通过人脸验证使用 TPM 保护的通行密钥"
                    opacity: 0.78
                    font.pointSize: 10
                }
            }

            Item { Layout.fillWidth: true }

            Controls.ToolButton {
                icon.name: "view-refresh"
                text: "刷新凭据"
                display: Controls.AbstractButton.IconOnly
                Accessible.name: "刷新凭据列表"
                Controls.ToolTip.visible: hovered
                Controls.ToolTip.text: "刷新凭据列表"
                onClicked: backend.refreshCredentials()
            }

            Controls.ToolButton {
                icon.name: "application-menu"
                text: "菜单"
                display: Controls.AbstractButton.IconOnly
                Accessible.name: text
                Controls.ToolTip.visible: hovered
                Controls.ToolTip.text: text
                onClicked: managerMenu.open()

                Controls.Menu {
                    id: managerMenu

                    Controls.MenuItem {
                        text: "设置"
                        icon.name: "configure"
                        onTriggered: settingsDialog.open()
                    }

                    Controls.MenuItem {
                        text: "关于 Gaze FIDO"
                        icon.name: "help-about"
                        onTriggered: aboutDialog.open()
                    }

                    Controls.MenuSeparator {}

                    Controls.MenuItem {
                        text: "退出 Gaze FIDO"
                        icon.name: "application-exit"
                        onTriggered: root.quitApplication()
                    }
                }
            }
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 22
        spacing: 14

        RowLayout {
            Layout.fillWidth: true
            Controls.Label {
                text: "已注册的网站"
                font.pointSize: 14
                font.weight: Font.DemiBold
            }
            Item { Layout.fillWidth: true }
            Controls.Label {
                text: `${root.sites.length} 个网站 · ${root.credentials.length} 个本机通行密钥`
                opacity: 0.75
            }
        }

        Kirigami.InlineMessage {
            Layout.fillWidth: true
            visible: backend.status_message.length > 0
            text: backend.status_message
            type: Kirigami.MessageType.Error
            showCloseButton: true
        }

        Item {
            Layout.fillWidth: true
            Layout.fillHeight: true

            ListView {
                id: siteList
                anchors.fill: parent
                clip: true
                model: root.sites
                spacing: 8
                boundsBehavior: Flickable.StopAtBounds
                flickableDirection: Flickable.VerticalFlick

                delegate: Controls.GroupBox {
                    id: siteGroup
                    required property var modelData
                    width: Math.max(0, siteList.width - siteScrollBar.width)
                    title: modelData.name

                    contentItem: ColumnLayout {
                        spacing: 4

                        RowLayout {
                            Layout.fillWidth: true
                            Controls.Label {
                                text: siteGroup.modelData.rpId
                                opacity: 0.75
                                elide: Text.ElideMiddle
                                Layout.fillWidth: true
                            }
                            Controls.Label {
                                text: `${siteGroup.modelData.credentials.length} 个通行密钥`
                                opacity: 0.7
                            }
                        }

                        Repeater {
                            model: siteGroup.modelData.credentials

                            delegate: Controls.ItemDelegate {
                                id: accountRow
                                required property var modelData
                                Layout.fillWidth: true
                                hoverEnabled: true
                                implicitHeight: 62
                                text: ""

                                contentItem: RowLayout {
                                    spacing: 10

                                    ColumnLayout {
                                        spacing: 2
                                        Layout.fillWidth: true
                                        Controls.Label {
                                            text: accountRow.modelData.display_name
                                                    || accountRow.modelData.username
                                                    || "未命名账号"
                                            font.weight: Font.Medium
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                        Controls.Label {
                                            text: `${root.formatCreated(accountRow.modelData.created)}  ·  Gaze 人脸验证  ·  TPM 保护`
                                            opacity: 0.72
                                            font.pointSize: 9
                                            elide: Text.ElideRight
                                            Layout.fillWidth: true
                                        }
                                    }

                                    Controls.ToolButton {
                                        icon.name: "edit-delete"
                                        display: Controls.AbstractButton.IconOnly
                                        Accessible.name: "删除此通行密钥"
                                        opacity: accountRow.hovered || accountRow.activeFocus ? 1 : 0
                                        enabled: accountRow.hovered || accountRow.activeFocus
                                        Behavior on opacity {
                                            NumberAnimation { duration: 120 }
                                        }
                                        Controls.ToolTip.visible: hovered
                                        Controls.ToolTip.text: "删除此通行密钥"
                                        onClicked: {
                                            deleteConfirmation.credential = accountRow.modelData
                                            deleteConfirmation.open()
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                Controls.ScrollBar.vertical: Controls.ScrollBar {
                    id: siteScrollBar
                    width: 14
                    policy: Controls.ScrollBar.AsNeeded
                }

                WheelHandler {
                    target: null
                    acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad
                    onWheel: function(event) {
                        const delta = event.pixelDelta.y !== 0
                                ? event.pixelDelta.y
                                : event.angleDelta.y / 120 * 54
                        const maximum = Math.max(0, siteList.contentHeight - siteList.height)
                        wheelAnimation.stop()
                        wheelAnimation.to = Math.max(0, Math.min(maximum, siteList.contentY - delta))
                        wheelAnimation.start()
                        event.accepted = true
                    }
                }
            }

            NumberAnimation {
                id: wheelAnimation
                target: siteList
                property: "contentY"
                duration: 170
                easing.type: Easing.OutCubic
            }

            Kirigami.PlaceholderMessage {
                anchors.centerIn: parent
                visible: root.credentials.length === 0 && backend.service_available
                icon.name: "key"
                text: "尚未注册通行密钥"
                explanation: "在支持安全密钥的网站注册后，凭据会显示在这里。"
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Kirigami.Icon {
                source: "dialog-information"
                implicitWidth: 16
                implicitHeight: 16
                opacity: 0.72
            }
            Controls.Label {
                text: "删除只会移除本机凭据；网站账户中的注册记录需单独删除。"
                opacity: 0.76
                font.pointSize: 9
                Layout.fillWidth: true
            }
        }
    }

    Controls.Dialog {
        id: settingsDialog
        modal: true
        anchors.centerIn: Controls.Overlay.overlay
        title: "Gaze FIDO 设置"

        contentItem: ColumnLayout {
            spacing: 10
            implicitWidth: 380

            Controls.CheckBox {
                Layout.fillWidth: true
                text: "显示托盘图标"
                checked: appSettings.showTrayIcon
                onToggled: appSettings.showTrayIcon = checked
            }

            Controls.Label {
                Layout.fillWidth: true
                text: "隐藏图标只隐藏托盘入口，桌面伴随程序和认证服务仍会在后台运行。再次启动 Gaze FIDO 可重新打开管理界面。"
                wrapMode: Text.WordWrap
                opacity: 0.78
            }
        }

        footer: Controls.DialogButtonBox {
            alignment: Qt.AlignRight

            Controls.Button {
                text: "完成"
                Controls.DialogButtonBox.buttonRole: Controls.DialogButtonBox.AcceptRole
                onClicked: settingsDialog.accept()
            }
        }
    }

    Controls.Dialog {
        id: aboutDialog
        modal: true
        anchors.centerIn: Controls.Overlay.overlay
        title: "关于 Gaze FIDO"

        contentItem: ColumnLayout {
            spacing: 8
            implicitWidth: 360

            Controls.Label {
                Layout.fillWidth: true
                text: `Gaze FIDO v${backend.app_version}`
                font.pointSize: 15
                font.weight: Font.DemiBold
            }

            Controls.Label {
                Layout.fillWidth: true
                text: "Linux 虚拟 FIDO2 身份验证器，使用 Gaze 人脸验证和 TPM 保护的通行密钥。"
                wrapMode: Text.WordWrap
            }
        }

        footer: Controls.DialogButtonBox {
            alignment: Qt.AlignRight

            Controls.Button {
                text: "关闭"
                Controls.DialogButtonBox.buttonRole: Controls.DialogButtonBox.AcceptRole
                onClicked: aboutDialog.accept()
            }
        }
    }

    Controls.Dialog {
        id: deleteConfirmation
        modal: true
        anchors.centerIn: Controls.Overlay.overlay
        title: "删除本机通行密钥？"
        property var credential: ({})

        contentItem: Controls.Label {
            text: `删除 ${deleteConfirmation.credential.display_name || deleteConfirmation.credential.username || "此账号"} 在 ${deleteConfirmation.credential.rp_id || "此网站"} 的本机凭据？`
            wrapMode: Text.WordWrap
            width: 340
        }

        footer: Controls.DialogButtonBox {
            alignment: Qt.AlignRight

            Controls.Button {
                text: "取消"
                Controls.DialogButtonBox.buttonRole: Controls.DialogButtonBox.RejectRole
                onClicked: deleteConfirmation.close()
            }

            Controls.Button {
                text: "删除"
                highlighted: true
                Controls.DialogButtonBox.buttonRole: Controls.DialogButtonBox.DestructiveRole
                onClicked: {
                    const token = deleteConfirmation.credential.token || ""
                    deleteConfirmation.close()
                    backend.deleteCredential(token)
                }
            }
        }
    }

    Controls.ApplicationWindow {
        id: verificationWindow
        width: 430
        height: 290
        minimumWidth: 400
        minimumHeight: 270
        visible: false
        title: "Gaze 人脸验证"
        flags: Qt.Dialog | Qt.WindowStaysOnTopHint
        transientParent: null
        modality: Qt.ApplicationModal

        ColumnLayout {
            anchors.fill: parent
            anchors.margins: 22
            spacing: 12

            Kirigami.Icon {
                source: "face-smile"
                implicitWidth: 56
                implicitHeight: 56
                Layout.alignment: Qt.AlignHCenter
            }

            Controls.Label {
                text: activePrompt.operation || "确认是你本人"
                font.pointSize: 14
                font.weight: Font.DemiBold
                horizontalAlignment: Text.AlignHCenter
                Layout.fillWidth: true
            }
            Controls.Label {
                text: activePrompt.rp_id || "未知网站"
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WrapAnywhere
                Layout.fillWidth: true
            }
            Controls.Label {
                visible: Boolean(activePrompt.account)
                text: activePrompt.account ? `账号：${activePrompt.account}` : ""
                opacity: 0.75
                horizontalAlignment: Text.AlignHCenter
                Layout.fillWidth: true
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 10
                Controls.BusyIndicator {
                    running: promptBusy
                    visible: promptBusy
                    implicitWidth: 28
                    implicitHeight: 28
                }
                Controls.Label {
                    text: promptBusy
                            ? (verificationWindow.cancelPending ? "正在取消验证…" : "请看向摄像头，等待 Gaze 验证")
                            : promptResult
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
            }

            Item { Layout.fillHeight: true }

            RowLayout {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignRight
                Controls.Button {
                    text: "取消"
                    enabled: promptBusy && !verificationWindow.cancelPending
                    onClicked: root.cancelVerification()
                }
            }
        }

        property bool cancelPending: false

        onVisibleChanged: {
            if (visible) {
                cancelPending = false
            } else {
                activeRequestId = ""
                promptResult = ""
            }
        }
        onClosing: function(close) {
            if (root.promptBusy) {
                close.accepted = false
                root.cancelVerification()
            }
        }
    }

    Timer {
        interval: 100
        repeat: true
        running: true
        onTriggered: backend.pollEvents()
    }

    Timer {
        interval: 8000
        repeat: true
        running: true
        onTriggered: backend.refreshCredentials()
    }

    Timer {
        id: closePromptTimer
        interval: 1100
        onTriggered: {
            if (!root.promptBusy)
                verificationWindow.close()
        }
    }

    Connections {
        target: backend
        function onPrompt_requested_jsonChanged() {
            root.openVerificationPrompt(backend.prompt_requested_json)
        }
        function onPrompt_finished_jsonChanged() {
            root.finishVerification(backend.prompt_finished_json)
        }
    }
}
