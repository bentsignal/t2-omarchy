---
name: cross-os-discovery
description: Use while doing cross-OS discovery between macOS and Linux on the same dual-boot machine.
---

# Cross-OS discovery

One physical Mac runs either Linux or macOS, never both. Each OS has its own
independent Codex thread. The threads cannot see each other's conversation,
terminal, processes, or uncommitted files, and the inactive OS's thread is not
running.

Use GitHub `main` as the handoff channel:

1. Establish the locally booted OS. Fetch `origin/main` and inspect commits
   after local `HEAD` before inferring what the other thread completed.
2. Before asking Shawn to reboot, commit and push all durable work and a precise
   handoff. Never commit credentials, biometric material, or temporary transfer
   artifacts.
3. State which OS Shawn should boot and acknowledge that this thread stops when
   its OS shuts down. Do not claim work here continues in the other OS.
4. When Shawn returns to this OS/thread, fetch and fast-forward, review the
   other thread's commits and authorized transfer artifacts, then continue from
   that evidence.

Call them the "Linux thread" and "macOS thread," not separate machines. The
other thread is invisible; Git commits are evidence of its work. If Shawn's
description and local Git state appear inconsistent, verify the remote before
explaining what happened.
