import importlib.util
import hashlib
import json
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
        self.assertTrue(result["helo_fields_exact"])
        self.assertTrue(result["helo_native_order_variant"])
        self.assertEqual(result["helo_native_order_variant_count"], 24)
        self.assertTrue(result["query_exact"])
        self.assertEqual(result["helo_size"], 119)
        self.assertEqual(result["query_size"], 62)
        self.assertEqual(
            hashlib.sha256(query).hexdigest(),
            "a60083fc2ec4be95418906235ac3024e9d01eb8661d82a34c2dea0bf3d0f4b1d")

    def test_semantic_helo_difference_is_reported_without_raw_bytes(self):
        helo = compare.bridge.encode_helo_frame(
            "other", 39, "biometrickitd", max_body=compare.CAP)
        query = compare.bridge.encode_bridge_version_query_frame(
            max_body=compare.CAP)
        result = compare.compare(helo, query, os_build="25G83", version=39,
                                 process_name="biometrickitd")
        self.assertFalse(result["helo_exact"])
        self.assertFalse(result["helo_fields_exact"])
        self.assertFalse(result["helo_native_order_variant"])
        self.assertIsInstance(result["helo_first_difference"], int)
        self.assertNotIn(helo.hex(), repr(result))

    def test_accepts_native_foundation_key_order_variance(self):
        fields = {
            "OSBuild": "25G83",
            "BridgeXPCVersion": 39,
            "ProcessName": "biometrickitd",
            "MaxSupportedProtocolVersion": 1,
        }
        body = json.dumps(fields, separators=(",", ":")).encode()
        helo = (compare.bridge.encode_frame_header(compare.bridge.FRAME_HELO,
                                                   len(body)) + body)
        query = compare.bridge.encode_bridge_version_query_frame(
            max_body=compare.CAP)
        result = compare.compare(helo, query, os_build="25G83", version=39,
                                 process_name="biometrickitd")
        self.assertFalse(result["helo_exact"])
        self.assertTrue(result["helo_fields_exact"])
        self.assertTrue(result["helo_native_order_variant"])
        self.assertTrue(result["query_exact"])

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
