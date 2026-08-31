#!/usr/bin/env python3
"""Verify current macOS calibration retrieval and accessory-cache ABI."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import struct
import subprocess


MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_X86_64 = 0x01000007
DAEMON_SHA256 = "248d4521007f95c916ae682c1a3d13d1c431626f4be4e84a0758d6dfbc94ce20"
SUPPORT_UUID = "93788D32-9E1E-37CE-8E4A-EBE8ECBD6735"
SUPPORT_TEXT_SHA256 = "f356bdc6419cb93dc3f0f8c40ffca8bc5bb7894b407264f9eeac06ddb2b103bc"
SUPPORT_PATH = "/System/Library/PrivateFrameworks/BiometricSupport.framework/Versions/A/BiometricSupport"

REQUIRED = (
    b"calibrationDataFromEEPROM\0",
    b"calibrationDataFromFDR\0",
    b"loadCalibrationData\0",
    b"performGetBiometrickitdInfoCommand:\0",
    b"performGetBioDeviceListCommand:\0",
    b"accessoryInfo:\0",
    b"getSensorType\0",
    b'{?="version"I"structSize"I"sensorType"I}\0',
)

# Method 5/11 use identical no-argument, one-object NSData reply validation.
EEPROM_METHOD = bytes.fromhex(
    "488d5dd048c70300000000488b35d9071100488d1592d50f004889d9")
FDR_METHOD = bytes.fromhex(
    "488d5dd048c70300000000488b35c8061100488d1599d40f004889d9")

# Generation >1 uses command 0x52 v1 with no input and a caller-supplied output
# capacity. The returned length is later required to be a bounded multiple of
# the exact 44-byte bio-device record size.
BIO_DEVICE_LIST = bytes.fromhex(
    "488b359b420f004c89f7ba5200000031c94531c04531c941545041ffd7")

# accessoryInfo: initializes an 83-byte output and the 20-byte input as type 2
# followed by 16 UUID bytes. It then sends command 0x54 v1/value zero and
# requires status zero plus an exact 83-byte reply before inspecting byte zero.
ACCESSORY_INFO_INPUT = bytes.fromhex(
    "418364244f00488d85f8feffff48c7005300000041c746fc02000000")
ACCESSORY_INFO_COMMAND = bytes.fromhex(
    "488b3544de06006a545a4c8d45bc6a1441594889df31c9"
    "488d85f8feffff5041544c89eb41ffd54883c41085c00f8534010000"
    "4883bdf8feffff530f85bc01000080bd60ffffff000f8446020000")

# The compatibility record is accessory type 1 + zero UUID, group type 1 +
# zero UUID, and flags 6. uuid_clear calls lie between these stores.
BUILTIN_RECORD_PREFIX = bytes.fromhex(
    "41bf01000000448938488d7804")
BUILTIN_RECORD_GROUP = bytes.fromhex("45897e14")
BUILTIN_RECORD_FLAGS = bytes.fromhex("41c7462806000000")

# Command 0x35 stores exactly three uint32 fields; getSensorType validates
# structSize (offset 4) equals 12 and returns sensorType (offset 8).
SENSOR_INFO = bytes.fromhex(
    "41b90c0000004889dfba3500000031c9")
SENSOR_INFO_STORE = bytes.fromhex(
    "488b4dd048890c038b4dd8894c0308")
SENSOR_TYPE_GETTER = bytes.fromhex("42837c37040c")

# BiometricSupport cacheAccessories implementation prologue and its local
# 44-byte fallback allocation. The full __text checksum pins all intervening
# object construction and reconciliation control flow.
SUPPORT_CACHE_PROLOGUE = bytes.fromhex(
    "554889e54157415641554154534881ec08030000")
SUPPORT_RECORD_ALLOCATION = bytes.fromhex("ba2c000000")


class EvidenceError(ValueError):
    pass


def inspect(daemon: bytes, support_text: bytes, support_uuid: str) -> dict[str, object]:
    if len(daemon) < 32 or struct.unpack_from("<II", daemon) != (MH_MAGIC_64, CPU_TYPE_X86_64):
        raise EvidenceError("daemon is not a thin x86_64 Mach-O")
    missing = [item.rstrip(b"\0").decode() for item in REQUIRED if item not in daemon]
    patterns = (EEPROM_METHOD, FDR_METHOD, BIO_DEVICE_LIST,
                ACCESSORY_INFO_INPUT, ACCESSORY_INFO_COMMAND,
                BUILTIN_RECORD_PREFIX, BUILTIN_RECORD_GROUP,
                BUILTIN_RECORD_FLAGS, SENSOR_INFO, SENSOR_INFO_STORE,
                SENSOR_TYPE_GETTER)
    if missing or any(daemon.count(pattern) != 1 for pattern in patterns):
        raise EvidenceError("missing or ambiguous daemon calibration/accessory evidence")
    if support_uuid.upper() != SUPPORT_UUID:
        raise EvidenceError("BiometricSupport UUID does not match")
    if support_text.count(SUPPORT_CACHE_PROLOGUE) != 1 or SUPPORT_RECORD_ALLOCATION not in support_text:
        raise EvidenceError("missing BiometricSupport cacheAccessories evidence")
    return {
        "daemon_sha256": hashlib.sha256(daemon).hexdigest(),
        "support_text_sha256": hashlib.sha256(support_text).hexdigest(),
        "eeprom_method": 5,
        "fdr_method": 11,
        "bio_device_command": 0x52,
        "bio_device_record_size": 44,
        "accessory_info_command": 0x54,
        "accessory_info_input_size": 20,
        "accessory_info_output_size": 83,
        "sensor_info_size": 12,
    }


def _support_evidence(path: str) -> tuple[bytes, str]:
    uuid_output = subprocess.run(
        ["/usr/bin/dyld_info", "-uuid", path], check=True,
        text=True, capture_output=True).stdout
    match = re.search(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}", uuid_output, re.I)
    if not match:
        raise EvidenceError("could not read BiometricSupport UUID")
    text_output = subprocess.run(
        ["/usr/bin/dyld_info", "-section_bytes", "__TEXT", "__text", path],
        check=True, text=True, capture_output=True).stdout
    rows = re.findall(r"^0x[0-9A-Fa-f]+:\s*((?:[0-9A-Fa-f]{2} ?)+)", text_output, re.M)
    if not rows:
        raise EvidenceError("could not read BiometricSupport __text")
    return bytes.fromhex("".join(rows)), match.group(0).upper()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("daemon", type=Path)
    parser.add_argument("--support", default=SUPPORT_PATH)
    args = parser.parse_args()
    support_text, support_uuid = _support_evidence(args.support)
    result = inspect(args.daemon.read_bytes(), support_text, support_uuid)
    if result["daemon_sha256"] != DAEMON_SHA256:
        raise SystemExit("biometrickitd SHA-256 does not match")
    if result["support_text_sha256"] != SUPPORT_TEXT_SHA256:
        raise SystemExit("BiometricSupport __text SHA-256 does not match")
    print("verified calibration/accessory ABI: "
          f"methods={result['eeprom_method']},{result['fdr_method']} "
          f"bio_device_command=0x{result['bio_device_command']:x} "
          f"record_size={result['bio_device_record_size']} "
          f"accessory_info_command=0x{result['accessory_info_command']:x} "
          f"accessory_info_io={result['accessory_info_input_size']}/"
          f"{result['accessory_info_output_size']} "
          f"sensor_info_size={result['sensor_info_size']}")


if __name__ == "__main__":
    main()
