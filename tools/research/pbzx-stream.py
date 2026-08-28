#!/usr/bin/env python3
"""Decode an Apple pbzx stream to stdout with bounded per-chunk memory.

This avoids `ipsw pkg`'s whole-payload buffering when selectively extracting
large macOS Core.pkg archives.  Pipe stdout directly into bsdtar.
"""

import argparse
import lzma
import struct
import sys


DEFAULT_CHUNK_CAP = 256 * 1024 * 1024
DEFAULT_LZMA_MEMLIMIT = 512 * 1024 * 1024


def read_exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise EOFError(f"short read: wanted {size} bytes, got {len(data)}")
    return data


def decode(source, destination, *, chunk_cap, lzma_memlimit):
    if read_exact(source, 4) != b"pbzx":
        raise ValueError("not a pbzx stream")
    read_exact(source, 8)  # advertised block size; per-chunk sizes are authoritative

    chunks = total = 0
    while True:
        header = source.read(16)
        if not header:
            break
        if len(header) != 16:
            raise EOFError("truncated pbzx chunk header")
        inflated_size, stored_size = struct.unpack(">QQ", header)
        if stored_size > inflated_size:
            raise ValueError(f"chunk {chunks}: stored size exceeds output size")
        if max(stored_size, inflated_size) > chunk_cap:
            raise ValueError(f"chunk {chunks}: size exceeds configured chunk cap")

        stored = read_exact(source, stored_size)
        if stored_size == inflated_size:
            output = stored
        else:
            output = lzma.decompress(stored, memlimit=lzma_memlimit)
            if len(output) != inflated_size:
                raise ValueError(
                    f"chunk {chunks}: expected {inflated_size} bytes, got {len(output)}"
                )
        destination.write(output)
        total += len(output)
        chunks += 1
    destination.flush()
    return chunks, total


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chunk-cap", type=int, default=DEFAULT_CHUNK_CAP)
    parser.add_argument("--lzma-memlimit", type=int, default=DEFAULT_LZMA_MEMLIMIT)
    args = parser.parse_args()
    if args.chunk_cap <= 0 or args.lzma_memlimit <= 0:
        parser.error("memory limits must be positive")
    chunks, total = decode(sys.stdin.buffer, sys.stdout.buffer,
                           chunk_cap=args.chunk_cap,
                           lzma_memlimit=args.lzma_memlimit)
    print(f"decoded {chunks} chunks ({total} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
