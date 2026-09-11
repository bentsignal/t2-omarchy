  property var gpuState: ({ mode: "auto", level: "unknown" })

  function setGpuMode(mode) {
    if (gpuAction.running) return
    gpuAction.command = ["/usr/local/bin/t2-gpu", mode]
    gpuAction.running = true
  }

  Process {
    id: gpuStatusProc
    command: ["/usr/local/bin/t2-gpu", "status"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try { root.gpuState = JSON.parse(text) }
        catch (e) { root.gpuState = { error: "Cannot read GPU status" } }
      }
    }
  }
  Process {
    id: gpuAction
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        if (text.trim()) {
          try { root.gpuState = JSON.parse(text) } catch (e) {}
        }
      }
    }
    onExited: root.refresh()
  }
