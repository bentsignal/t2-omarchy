#!/usr/bin/env python3
"""Verify one captured, bounded T2 SEP discovery log from stdin.

This is an offline parser.  It does not read the kernel journal, load a module,
or access hardware; run-discovery.sh supplies only the cursor-bounded text from
its future privileged experiment.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib.util
from pathlib import Path
import re
import sys


MODULE_PATH = Path(__file__).with_name("decode-message.py")
SPEC = importlib.util.spec_from_file_location("decode_message", MODULE_PATH)
assert SPEC and SPEC.loader
discovery = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = discovery
SPEC.loader.exec_module(discovery)


class VerificationError(ValueError):
    pass


CANDIDATE = re.compile(
    r"discovery candidate (\d+): ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) "
    r"([0-9a-fA-F]{8}) ([0-9a-fA-F]{8})"
)
IDENTITY = re.compile(
    r"discovery identity: id=(?:0x)?([0-9a-fA-F]+) name=([0-9a-fA-F]{8})"
)
LIMITS = re.compile(
    r"discovery OOL: id=(?:0x)?([0-9a-fA-F]+) "
    r"in=(\d+)\.\.(\d+) pages out=(\d+)\.\.(\d+) pages"
)
SUMMARY = re.compile(
    r"bounded discovery complete: records=(\d+) identities=(\d+) "
    r"sbio=(yes|no) limits=(yes|no) result=(-?\d+)"
)
FAILURE_WORDS = re.compile(
    r"\b(error|failed|skipped|timed out|invalid|duplicate|inverted|lacks|outside)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class VerificationResult:
    records: int
    identities: int
    sbio_limits: tuple[int, int, int, int]


def verify_log(text: str) -> VerificationResult:
    if not isinstance(text, str):
        raise VerificationError("discovery log must be text")
    table = discovery.DiscoveryTable()
    nop_count = 0
    summary_count = 0
    stop_count = 0
    records = 0
    detail_expected: discovery.EndpointInfo | None = None
    detail_count = 0
    summary_values: tuple[int, int, str, str, int] | None = None
    summary_seen = False

    for line in text.splitlines():
        if "t2sep_probe" not in line:
            continue
        if FAILURE_WORDS.search(line):
            raise VerificationError(f"probe log contains a failure: {line.strip()}")
        if "control NOP response passed strict validation" in line:
            if records or summary_seen:
                raise VerificationError("validated NOP appears after discovery began")
            nop_count += 1
            if nop_count > 1:
                raise VerificationError("multiple validated NOP sessions are mixed")
            continue

        match = CANDIDATE.search(line)
        if match:
            if nop_count != 1 or summary_seen:
                raise VerificationError("discovery record is outside the validated session")
            if detail_expected is not None:
                raise VerificationError("previous discovery record lacks its detail log")
            index = int(match.group(1))
            if index != records:
                raise VerificationError("discovery candidate indices are skipped or repeated")
            words = [int(value, 16) for value in match.groups()[1:]]
            try:
                detail_expected = table.accept(words)
            except discovery.DiscoveryError as error:
                raise VerificationError("candidate record failed offline replay") from error
            records += 1
            continue

        match = IDENTITY.search(line)
        if match:
            if detail_expected is None or detail_expected.limits is not None:
                raise VerificationError("unexpected discovery identity detail")
            if (int(match.group(1), 16), int(match.group(2), 16)) != (
                    detail_expected.endpoint_id, detail_expected.name):
                raise VerificationError("identity detail disagrees with candidate record")
            detail_expected = None
            detail_count += 1
            continue

        match = LIMITS.search(line)
        if match:
            if detail_expected is None or detail_expected.limits is None:
                raise VerificationError("unexpected discovery OOL detail")
            logged = (int(match.group(1), 16),
                      *(int(value) for value in match.groups()[1:]))
            if logged != (detail_expected.endpoint_id, *detail_expected.limits):
                raise VerificationError("OOL detail disagrees with candidate record")
            detail_expected = None
            detail_count += 1
            continue

        match = SUMMARY.search(line)
        if match:
            if nop_count != 1 or detail_expected is not None:
                raise VerificationError("discovery summary is premature")
            summary_count += 1
            if summary_count > 1:
                raise VerificationError("multiple discovery summaries are mixed")
            summary_values = (int(match.group(1)), int(match.group(2)),
                              match.group(3), match.group(4), int(match.group(5)))
            summary_seen = True
            continue

        if "issued Apple CPU-stop value 5" in line:
            if not summary_seen:
                raise VerificationError("transport stopped before discovery summary")
            stop_count += 1
            if stop_count > 1:
                raise VerificationError("multiple transport-stop records are mixed")

    if nop_count != 1:
        raise VerificationError("exactly one validated control NOP is required")
    if records == 0 or detail_expected is not None or detail_count != records:
        raise VerificationError("discovery candidate/detail transcript is incomplete")
    if summary_count != 1 or summary_values is None:
        raise VerificationError("exactly one discovery summary is required")
    if stop_count != 1:
        raise VerificationError("exactly one post-discovery transport stop is required")
    try:
        sbio = table.finalize_sbio()
    except discovery.DiscoveryError as error:
        raise VerificationError("offline replay did not produce usable sbio") from error
    expected_summary = (records, len(table.endpoints), "yes", "yes", 0)
    if summary_values != expected_summary:
        raise VerificationError("kernel summary disagrees with offline replay")
    assert sbio.limits is not None
    return VerificationResult(records, len(table.endpoints), sbio.limits)


def main() -> None:
    try:
        result = verify_log(sys.stdin.read())
    except VerificationError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print(f"verified discovery: records={result.records} "
          f"identities={result.identities} sbio_limits={result.sbio_limits}")


if __name__ == "__main__":
    main()
