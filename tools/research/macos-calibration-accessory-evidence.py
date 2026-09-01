#!/usr/bin/env python3
"""Verify current macOS calibration, accessory, and match-command ABI."""

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
    b"performMatchCommand:\0",
    b"selectedIdentitiesBlob\0",
    b"processedFlags\0",
    b"appendData:\0",
    b"systemSleepStateChanged:\0",
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

# performMatchCommand: allocates the zero-filled 68-byte base input, stores
# processedFlags and userID in its first two words, and clears flag bit 0x80.
MATCH_BASE_INPUT = bytes.fromhex(
    "488b3dfb780e00488b35ec8c1000ba44000000ff15397a0e00"
    "4889c7e8d71d0b004989c54885db0f84150300004c89efe8b71d0b00"
    "488b35c68c10004c89efff150d7a0e004885c00f84020300004989c4"
    "4c8975c0488b35c68b10004c8b35ef790e004889df41ffd641890424"
    "488b351e7910004889df41ffd64189442404418024247f")

# The ordinary path obtains selectedIdentitiesBlob, appends that NSData
# unchanged when present, and sends command 4/value zero with no output.
MATCH_SELECTION_APPEND = bytes.fromhex(
    "4c8b3d098010004889df4c89feff151d780e004889c7e8bb1b0b00"
    "4989c44889c7ff1541780e004d85e4742d4889df4c89fe41ffd6"
    "4889c7e8991b0b004989c7488b35c18a10004c89ef4889c241ffd6"
    "4c89ffff150f780e004c89efe8691b0b00488b35207a10004c89ef"
    "41ffd64989c7488b35d07810004c89ef41ffd6488b35bb881000"
    "0f57c00f1104244c8b65c04c89e7ba0400000031c94d89f84989c141ffd6")

# BiometricMatchOperationMesa.selectedIdentities reads count at blob offset 0,
# starts records at offset 8, and advances by the 20-byte identity-record size.
MATCH_SELECTION_DECODE = bytes.fromhex(
    "488b3d6cd204008b13488b3573d6060041ffd74889c7e856770100"
    "4989c448895dd0833b00746b4c8b7dd04983c708488b05f5d50600"
    "488945c0488b0552d60600488945c831db488b3d2dd10400e89a760100"
    "4889c7488b75c04c89fa4c8b2d67d3040041ffd54989c64c89e7"
    "488b75c84889c241ffd54c89f7ff1583d3040048ffc3488b45d0"
    "8b004983c7144839c372b5")

# systemSleepStateChanged: forwards its Boolean as command 0x57's inValue with
# no input or output buffer. The successful lock-screen window uses value one
# before the first match start.
SYSTEM_SLEEP_STATE_COMMAND = bytes.fromhex(
    "410fbec6488b35a87710000f57c00f1104240fb7c84889df"
    "ba570000004531c04531c9ff157a660e00")

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

# The current BiometricMatchOperation initializer leaves Objective-C-zeroed
# flags/blob state intact and sets both user IDs to UINT32_MAX.
SUPPORT_MATCH_DEFAULTS = bytes.fromhex(
    "4885c0740bb9ffffffff894850894858")

# initMatchOperation defaults a missing BKFilterUserID to UINT32_MAX, reads a
# present filter's 32-bit value, and then applies that value to the operation.
SUPPORT_MATCH_USER_FILTER = bytes.fromhex(
    "4883bd08ffffff007436b8ffffffff488d95f8feffff488902"
    "488d351a7a9139488bbd08ffffffe8d84d010085c07415"
    "898548ffffff4531e431dbe96b0500006aff5aeb068b95f8feffff")

# The current superclass serializer maps selected-identity presence to 0x4000,
# forUnlock to 1, forCredentialSet to 8, forPreArm to 0x100,
# stopOnSuccess to 0x80, and noBioLockout to 0x10. The daemon later strips the
# stopOnSuccess bit before command 4.
SUPPORT_MATCH_FLAG_MAP = bytes.fromhex(
    "4c89a510ffffff4d85e4741f488b359dce91394c89ffffd30d00400000"
    "488b3594ce91394c89ff89c2ffd380bd4dffffff00741d488b3575ce9139"
    "4c89ffffd383c801488b356ece91394c89ff89c2ffd380bd00ffffff00741d"
    "488b354fce91394c89ffffd383c808488b3548ce91394c89ff89c2ffd3"
    "80bd4effffff004c8bb538ffffff4c8ba510ffffff741f488b351bce9139"
    "4c89ffffd30d00010000488b3512ce91394c89ff89c2ffd380bd4cffffff00"
    "741f488b35f3cd91394c89ffffd30d80000000488b35eacd91394c89ff"
    "89c2ffd3c78548ffffff0000000080bd4fffffff00741d488b35c1cd9139"
    "4c89ffffd383c810488b35bacd91394c89ff89c2ffd3")


class EvidenceError(ValueError):
    pass


def inspect(daemon: bytes, support_text: bytes, support_uuid: str) -> dict[str, object]:
    if len(daemon) < 32 or struct.unpack_from("<II", daemon) != (MH_MAGIC_64, CPU_TYPE_X86_64):
        raise EvidenceError("daemon is not a thin x86_64 Mach-O")
    missing = [item.rstrip(b"\0").decode() for item in REQUIRED if item not in daemon]
    patterns = (EEPROM_METHOD, FDR_METHOD, BIO_DEVICE_LIST,
                ACCESSORY_INFO_INPUT, ACCESSORY_INFO_COMMAND,
                MATCH_BASE_INPUT, MATCH_SELECTION_APPEND,
                MATCH_SELECTION_DECODE, SYSTEM_SLEEP_STATE_COMMAND,
                BUILTIN_RECORD_PREFIX, BUILTIN_RECORD_GROUP,
                BUILTIN_RECORD_FLAGS, SENSOR_INFO, SENSOR_INFO_STORE,
                SENSOR_TYPE_GETTER)
    if missing or any(daemon.count(pattern) != 1 for pattern in patterns):
        raise EvidenceError("missing or ambiguous daemon calibration/accessory evidence")
    if support_uuid.upper() != SUPPORT_UUID:
        raise EvidenceError("BiometricSupport UUID does not match")
    if (support_text.count(SUPPORT_CACHE_PROLOGUE) != 1
            or SUPPORT_RECORD_ALLOCATION not in support_text
            or support_text.count(SUPPORT_MATCH_DEFAULTS) != 1
            or support_text.count(SUPPORT_MATCH_USER_FILTER) != 1
            or support_text.count(SUPPORT_MATCH_FLAG_MAP) != 1):
        raise EvidenceError("missing BiometricSupport calibration/match evidence")
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
        "match_command": 4,
        "match_base_input_size": 68,
        "match_processed_flags_clear_mask": 0x80,
        "match_selection_header_size": 8,
        "match_selection_record_size": 20,
        "match_default_processed_flags": 0,
        "match_default_user_id": 0xFFFFFFFF,
        "match_user_id_is_filter_derived": True,
        "match_for_unlock_flags": 0x01,
        "match_for_prearm_flags": 0x100,
        "match_selected_identity_flags": 0x4000,
        "system_sleep_state_command": 0x57,
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
          f"match_command=0x{result['match_command']:x} "
          f"match_base={result['match_base_input_size']} "
          f"match_selection={result['match_selection_header_size']}+"
          f"n*{result['match_selection_record_size']} "
          f"sensor_info_size={result['sensor_info_size']}")


if __name__ == "__main__":
    main()
