import importlib.util
from pathlib import Path
import struct
import sys
import unittest


MODULE = Path(__file__).with_name("extract-legacy-dyld-image.py")
SPEC = importlib.util.spec_from_file_location("extract_legacy_dyld_image", MODULE)
assert SPEC and SPEC.loader
extractor = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = extractor
SPEC.loader.exec_module(extractor)


def cache_fixture():
    data = bytearray(0x2000)
    data[:16] = b"dyld_v1  armv7k\0"
    struct.pack_into("<IIII", data, 16, 0x98, 1, 0xb8, 1)
    struct.pack_into("<QQQII", data, 0x98, 0x10000000, 0x1000, 0x1000, 5, 5)
    struct.pack_into("<QQQII", data, 0xb8, 0x10000100, 0, 0, 0x300, 0)
    data[0x300:0x30b] = b"/TestImage\0"
    image = 0x1100
    struct.pack_into("<IIIIIII", data, image, extractor.MH_MAGIC, 12, 12,
                     6, 1, 56, 0)
    struct.pack_into("<II16sIIIIIIII", data, image + 28,
                     extractor.LC_SEGMENT, 56, b"__TEXT\0" + b"\0" * 9,
                     0x10000100, 0x100, 0, 0x100, 5, 5, 0, 0)
    data[image + 84:image + 0x100] = bytes(range(0x100 - 84))
    return bytes(data)


class LegacyDyldExtractorTests(unittest.TestCase):
    def test_extracts_one_bounded_image(self):
        result = extractor.extract(cache_fixture(), "/TestImage")
        self.assertEqual(len(result), 0x100)
        self.assertEqual(struct.unpack_from("<I", result)[0], extractor.MH_MAGIC)

    def test_rejects_wrong_path_and_truncation(self):
        with self.assertRaises(extractor.ExtractError):
            extractor.extract(cache_fixture(), "/Missing")
        with self.assertRaises(extractor.ExtractError):
            extractor.extract(cache_fixture()[:0x1050], "/TestImage")


if __name__ == "__main__":
    unittest.main()
