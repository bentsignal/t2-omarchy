# Dual-boot collaboration invariant

This repository is being developed on one physical T2 MacBook with two
mutually exclusive boot environments: Linux and macOS. Only one operating
system can run at a time.

There are two independent Codex threads:

- the Linux Codex thread runs only while Linux is booted;
- the macOS Codex thread runs only while macOS is booted.

The threads cannot see one another's conversation, terminal, processes, or
uncommitted filesystem state. Neither thread continues running while the other
OS is booted. Never describe them as concurrent machines or imply that one can
inspect/control the other thread.

GitHub `main` is the sole handoff channel. Apply this workflow whenever work
crosses the OS boundary:

1. Establish the currently booted OS from the local environment, not from an
   assumption about the other thread.
2. Fetch `origin/main` and inspect commits after local `HEAD` before deciding
   what the other OS completed. A remote commit is evidence; the other
   conversation is not visible.
3. Before requesting an OS switch, commit and push all durable code,
   documentation, tests, and a precise handoff. Keep sensitive biometric data,
   credentials, and temporary encrypted transfers out of Git.
4. Clearly tell Shawn which OS to boot and that the current Codex thread will
   stop during the reboot. Do not claim that work in this thread will continue
   while the other OS is active.
5. After Shawn returns to this OS/thread, fetch and fast-forward, review the
   new commits and any explicitly authorized local transfer artifacts, then
   continue from that evidence.

Use the labels "Linux thread" and "macOS thread" rather than "machine" when
distinguishing the two agents. If Git history and Shawn's description appear
to conflict, verify remote state first and explain the discrepancy without
inventing activity in the invisible thread.

This file is temporary project coordination infrastructure. Remove it when the
dual-boot reverse-engineering phase is complete.
