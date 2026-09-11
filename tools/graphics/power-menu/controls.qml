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
            width: parent.width
            text: root.gpuState.error ? "AMD control unavailable: " + root.gpuState.error
              : "AMD: " + (root.gpuState.level === "high" ? "Performance" : "Power saver")
                + (root.gpuState.mode === "auto" ? " (automatic)" : " (override)")
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
            text: "Auto follows Performance on AC and saves power on battery. Overrides reset when power is connected or disconnected."
            wrapMode: Text.WordWrap
            color: root.bar.foreground
            opacity: 0.7
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.bodySmall
          }
          Button {
            width: parent.width
            text: "Launch AMD browser"
            foreground: root.bar.foreground
            fontFamily: root.bar.fontFamily
            bordered: true
            onClicked: root.setGpuMode("browser")
          }
          Text {
            width: parent.width
            text: "Opens a separate browser profile for games. Existing windows keep their current GPU."
            wrapMode: Text.WordWrap
            color: root.bar.foreground
            opacity: 0.7
            font.family: root.bar.fontFamily
            font.pixelSize: Style.font.bodySmall
          }
        }
