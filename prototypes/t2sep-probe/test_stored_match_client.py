import importlib.util
from pathlib import Path
import sys
import unittest


PATH = Path(__file__).with_name("stored-match-client.py")
SPEC = importlib.util.spec_from_file_location("stored_match_client_tested", PATH)
client = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = client
SPEC.loader.exec_module(client)


class StoredMatchClientTests(unittest.TestCase):
    def test_import_cannot_enable_live_matching(self):
        self.assertFalse(client.match.LIVE_MATCH_ENABLED)

    def test_only_ready_event_requests_touch(self):
        messages = []
        original = __import__("builtins").print
        __import__("builtins").print = lambda *args, **kwargs: messages.append(" ".join(map(str, args)))
        try:
            client.progress((client.match.NONTERMINAL_READY, 1, 0))
            client.progress((0xE3FF800B, 1, 9))
        finally:
            __import__("builtins").print = original
        self.assertEqual(sum("TOUCH NOW" in message for message in messages), 1)


if __name__ == "__main__":
    unittest.main()
