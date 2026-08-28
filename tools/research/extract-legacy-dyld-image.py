#!/usr/bin/env python3
"""Extract one 32-bit image from a legacy, unslid dyld shared cache.

This intentionally supports only the small pre-dyld4 format needed by the
bridgeOS 3 recovery cache.  It rejects modern caches and never overwrites an
output file.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import struct


MH_MAGIC = 0xFEEDFACE
LC_SEGMENT = 0x1
MAX_CACHE = 512 * 1024 * 1024
MAX_IMAGE = 128 * 1024 * 1024


class ExtractError(ValueError):
    pass


def _cstring(data: bytes, offset: int) -> str:
    if not 0 <= offset < len(data):
        raise ExtractError("cache string offset is out of bounds")
    end = data.find(b"\0", offset, min(len(data), offset + 4096))
    if end < 0:
        raise ExtractError("cache string is unterminated")
    try:
        return data[offset:end].decode()
    except UnicodeDecodeError as error:
        raise ExtractError("cache string is not UTF-8") from error


def extract(data: bytes, image_path: str) -> bytes:
    if not isinstance(data, bytes) or not 32 <= len(data) <= MAX_CACHE:
        raise ExtractError("cache size is invalid")
    if not data[:16].startswith(b"dyld_v1  "):
        raise ExtractError("input is not a legacy dyld cache")
    mapping_offset, mapping_count, images_offset, images_count = \
        struct.unpack_from("<IIII", data, 16)
    if not 1 <= mapping_count <= 32 or not 1 <= images_count <= 10000:
        raise ExtractError("cache table counts are invalid")
    mappings = []
    for index in range(mapping_count):
        offset = mapping_offset + index * 32
        if offset + 32 > len(data):
            raise ExtractError("mapping table is truncated")
        address, size, file_offset, _, _ = struct.unpack_from("<QQQII", data, offset)
        if not size or file_offset + size > len(data):
            raise ExtractError("cache mapping is out of bounds")
        mappings.append((address, size, file_offset))

    matches = []
    for index in range(images_count):
        offset = images_offset + index * 32
        if offset + 32 > len(data):
            raise ExtractError("image table is truncated")
        address, _, _, path_offset, _ = struct.unpack_from("<QQQII", data, offset)
        if _cstring(data, path_offset) == image_path:
            matches.append(address)
    if len(matches) != 1:
        raise ExtractError("image path must match exactly one cache image")

    def cache_offset(address: int, size: int) -> int:
        for base, length, file_offset in mappings:
            if base <= address and size <= base + length - address:
                return file_offset + address - base
        raise ExtractError("image address is outside cache mappings")

    header_offset = cache_offset(matches[0], 28)
    if struct.unpack_from("<I", data, header_offset)[0] != MH_MAGIC:
        raise ExtractError("image is not a 32-bit little-endian Mach-O")
    command_count, command_size = struct.unpack_from("<II", data, header_offset + 16)
    if command_count > 1024 or command_size > 1024 * 1024:
        raise ExtractError("Mach-O load-command bounds are invalid")
    cursor = header_offset + 28
    command_end = cursor + command_size
    if command_end > len(data):
        raise ExtractError("Mach-O load commands are truncated")
    segments = []
    section_offset_patches = []
    output_size = 0
    for _ in range(command_count):
        if cursor + 8 > command_end:
            raise ExtractError("Mach-O load command is truncated")
        command, size = struct.unpack_from("<II", data, cursor)
        if size < 8 or cursor + size > command_end:
            raise ExtractError("Mach-O load-command size is invalid")
        if command == LC_SEGMENT:
            if size < 56:
                raise ExtractError("Mach-O segment command is truncated")
            vm_address, vm_size, file_offset, file_size = struct.unpack_from(
                "<IIII", data, cursor + 24)
            section_count = struct.unpack_from("<I", data, cursor + 48)[0]
            if 56 + section_count * 68 > size:
                raise ExtractError("Mach-O section table is truncated")
            if file_size > vm_size or file_offset + file_size > MAX_IMAGE:
                raise ExtractError("Mach-O segment bounds are invalid")
            if file_size:
                segments.append((vm_address, file_offset, file_size))
                output_size = max(output_size, file_offset + file_size)
            for section_index in range(section_count):
                section = cursor + 56 + section_index * 68
                section_address = struct.unpack_from("<I", data, section + 32)[0]
                section_size = struct.unpack_from("<I", data, section + 36)[0]
                section_type = struct.unpack_from("<I", data, section + 56)[0] & 0xff
                if not vm_address <= section_address or section_size > \
                        vm_address + vm_size - section_address:
                    raise ExtractError("Mach-O section is outside its segment")
                if section_size and section_type not in (1, 0xc, 0x12):
                    corrected = file_offset + section_address - vm_address
                    if corrected + section_size > file_offset + file_size:
                        raise ExtractError("Mach-O section file range is invalid")
                    section_offset_patches.append(
                        (section - header_offset + 40, corrected))
        cursor += size
    if cursor != command_end or not segments or output_size > MAX_IMAGE:
        raise ExtractError("Mach-O segment layout is invalid")
    output = bytearray(output_size)
    for vm_address, file_offset, file_size in segments:
        source = cache_offset(vm_address, file_size)
        output[file_offset:file_offset + file_size] = data[source:source + file_size]
    for patch_offset, corrected in section_offset_patches:
        struct.pack_into("<I", output, patch_offset, corrected)
    return bytes(output)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache", type=Path)
    parser.add_argument("image_path")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("output must not already exist")
    result = extract(args.cache.read_bytes(), args.image_path)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(result)
    print(f"extracted {len(result)} bytes")


if __name__ == "__main__":
    main()
