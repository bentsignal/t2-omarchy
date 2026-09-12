        PanelSeparator { foreground: root.bar.foreground }
        Column {
          width: parent.width
          spacing: Style.space(8)
          PanelSectionHeader {
            text: "AMD GRAPHICS"
            foreground: root.bar.foreground
            fontFamily: root.bar.fontFamily
          }
          Text {
            visible: !!root.gpuState.error
            width: parent.width
            text: root.gpuState.error ? "AMD control unavailable: " + root.gpuState.error : ""
            wrapMode: Text.WordWrap
            color: root.bar.foreground
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.bodySmall
          }
          Row {
            width: parent.width
            spacing: Style.space(6)
            Repeater {
              model: ["auto", "performance", "saver"]
              Button {
                required property string modelData
                width: (parent.width - parent.spacing * 2) / 3
                text: modelData === "auto" ? "Auto" : modelData === "performance" ? "Performance" : "Power saver"
                foreground: root.bar.foreground
                fontFamily: root.bar.fontFamily
                fontSize: Style.font.bodySmall
                bordered: true
                active: root.gpuState.mode === modelData
                onClicked: root.setGpuMode(modelData)
              }
            }
          }
          Text {
            width: parent.width
            text: "Auto: performance on AC, power saver on battery. Manual selections stay selected."
            wrapMode: Text.WordWrap
            color: root.bar.foreground
            opacity: 0.7
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.bodySmall
          }
        }
