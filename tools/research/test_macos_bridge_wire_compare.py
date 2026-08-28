import importlib.util
from pathlib import Path
import plistlib
import sys
import unittest


SPEC = importlib.util.spec_from_file_location(
    "macos_bridge_wire_compare",
    Path(__file__).with_name("macos-bridge-wire-compare.py"))
compare = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = compare
SPEC.loader.exec_module(compare)


class MacosBridgeWireCompareTests(unittest.TestCase):
    def test_exact_current_frames(self):
        helo = compare.bridge.encode_helo_frame(
            "25G83", 39, "biometrickitd", max_body=compare.CAP)
        query = compare.bridge.encode_bridge_version_query_frame(
            max_body=compare.CAP)
        result = compare.compare(helo, query, os_build="25G83", version=39,
                                 process_name="biometrickitd")
        self.assertTrue(result["helo_exact"])
        self.assertTrue(result["query_exact"])
        self.assertEqual(result["helo_size"], 119)
        self.assertEqual(result["query_size"], 62)

    def test_semantic_helo_difference_is_reported_without_raw_bytes(self):
        helo = compare.bridge.encode_helo_frame(
            "other", 39, "biometrickitd", max_body=compare.CAP)
        query = compare.bridge.encode_bridge_version_query_frame(
            max_body=compare.CAP)
        result = compare.compare(helo, query, os_build="25G83", version=39,
                                 process_name="biometrickitd")
        self.assertFalse(result["helo_exact"])
        self.assertIsInstance(result["helo_first_difference"], int)
        self.assertNotIn(helo.hex(), repr(result))

    def test_rejects_wrong_kind_trailing_bytes_and_nonzero_method(self):
        helo = compare.bridge.encode_helo_frame(
            "25G83", 39, "biometrickitd", max_body=compare.CAP)
        query = compare.bridge.encode_bridge_version_query_frame(
            max_body=compare.CAP)
        with self.assertRaises(compare.CompareError):
            compare.compare(query, query, os_build="25G83", version=39,
                            process_name="biometrickitd")
        with self.assertRaises(compare.CompareError):
            compare.compare(helo + b"x", query, os_build="25G83", version=39,
                            process_name="biometrickitd")
        method_one_body = plistlib.dumps([1], fmt=plistlib.FMT_BINARY,
                                         sort_keys=False)
        method_one = (compare.bridge.encode_frame_header(
            compare.bridge.FRAME_MESSAGE, len(method_one_body))
            + method_one_body)
        with self.assertRaises(compare.CompareError):
            compare.compare(helo, method_one, os_build="25G83", version=39,
                            process_name="biometrickitd")


if __name__ == "__main__":
    unittest.main()
