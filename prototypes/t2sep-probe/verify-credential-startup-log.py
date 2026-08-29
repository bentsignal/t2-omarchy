#!/usr/bin/env python3
"""Verify simultaneous AKS startup and ephemeral ACM context lifecycle."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys


class VerificationError(ValueError):
    pass


def _load(filename: str, name: str):
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dual = _load("verify-dual-credential-ool-log.py", "credential_startup_dual")
aks = _load("verify-aks-startup-environment-log.py", "credential_startup_aks")
acm = _load("verify-acm-context-lifecycle-log.py", "credential_startup_acm")


def verify(text: str) -> int:
    if not isinstance(text, str):
        raise VerificationError("combined credential startup transcript must be text")
    try:
        profiles = dual.verify(text)
        if profiles != ((7, 1, 7), (7, 1, 7), (10, 1, 10), (10, 1, 10)):
            raise VerificationError("simultaneous OOL profiles changed")
        version = aks.verify_service(text)
        acm.verify_service(text)
    except (dual.VerificationError, aks.VerificationError,
            acm.VerificationError) as error:
        raise VerificationError(str(error)) from error

    aks_done = text.find("AKS startup environment reply passed strict validation:")
    acm_started = text.find("ACM SCRD initialization request:")
    if aks_done < 0 or acm_started < 0 or aks_done >= acm_started:
        raise VerificationError("AKS startup did not complete before ACM startup")
    return version


def main() -> None:
    try:
        version = verify(sys.stdin.read())
    except (ValueError, VerificationError) as error:
        print(f"combined credential startup verification failed: {error}",
              file=sys.stderr)
        raise SystemExit(1)
    print(f"verified simultaneous AKS/ACM startup: header_version={version}")


if __name__ == "__main__":
    main()
