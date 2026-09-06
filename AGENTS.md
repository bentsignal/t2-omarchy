# Project scope

This project closes gaps between Intel T2 Macs and Linux, including hardware
enablement, reproducible setup, reverse engineering, and upstream-quality
documentation. Preserve evidence, tests, and safety boundaries so discoveries
can become usable Linux support rather than machine-specific experiments.

# External repositories

This Git checkout is the project, regardless of OS or absolute path. Start with
[development workspace](docs/development-workspace.md) and the
[current Touch ID roadmap](docs/touch-id-roadmap.md).

Treat external checkouts, including `.local/references/` inside this workspace,
as read-only references, not extra project worktrees.
Do not modify files, create branches or commits, push changes, or open pull
requests in external repositories unless Shawn explicitly authorizes it. Keep
all project implementation, tests, tooling, and documentation in this repository.

`.local/` is ignored local support material, not project source. Do not index,
upload, commit, or broadly scan it: it includes large vendor images and private
captures. Read only the specific reference needed. Installed authentication
files under `/opt`, `/usr/local`, and `/var/lib` are not disposable build output.
