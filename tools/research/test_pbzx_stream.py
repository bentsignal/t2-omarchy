import importlib.util
import io
import lzma
from pathlib import Path
import struct
import sys
import unittest


MODULE_PATH = Path(__file__).with_name("pbzx-stream.py")
SPEC = importlib.util.spec_from_file_location("pbzx_stream", MODULE_PATH)
pbzx = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = pbzx
SPEC.loader.exec_module(pbzx)


def stream(chunks):
    result = bytearray(b"pbzx" + (1 << 24).to_bytes(8, "big"))
    for inflated, stored in chunks:
        result += struct.pack(">QQ", len(inflated), len(stored)) + stored
    return io.BytesIO(result)


class PBZXTests(unittest.TestCase):
    def test_raw_and_compressed_chunks(self):
        raw = b"raw"
        expanded = b"compressed" * 100
        source = stream([(raw, raw), (expanded, lzma.compress(expanded))])
        output = io.BytesIO()
        self.assertEqual(
            pbzx.decode(source, output, chunk_cap=4096, lzma_memlimit=64 << 20),
            (2, len(raw) + len(expanded)),
        )
        self.assertEqual(output.getvalue(), raw + expanded)

    def test_rejects_bad_magic_truncation_and_oversize(self):
        for source in (io.BytesIO(b"bad!" + b"\0" * 8),
                       io.BytesIO(b"pbzx" + b"\0" * 8 + b"x")):
            with self.assertRaises((ValueError, EOFError)):
                pbzx.decode(source, io.BytesIO(), chunk_cap=16,
                            lzma_memlimit=1 << 20)
        source = stream([(b"x" * 17, b"x" * 17)])
        with self.assertRaises(ValueError):
            pbzx.decode(source, io.BytesIO(), chunk_cap=16,
                        lzma_memlimit=1 << 20)


if __name__ == "__main__":
    unittest.main()
