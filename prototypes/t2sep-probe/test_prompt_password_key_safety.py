from pathlib import Path
import unittest


SOURCE = Path(__file__).with_name("prompt-password-key.sh").read_text()


class PromptPasswordKeySafetyTests(unittest.TestCase):
    def test_password_is_piped_directly_into_kernel_keyring(self):
        self.assertIn("systemd-ask-password", SOURCE)
        self.assertIn("keyctl padd user", SOURCE)
        self.assertNotIn("password=$(", SOURCE)
        self.assertNotIn("read -r password", SOURCE)

    def test_prompt_is_hidden_bounded_and_requires_fifo(self):
        for fragment in ("--echo=no", "--timeout=120", "[[ -p $fifo ]]", "set +x"):
            self.assertIn(fragment, SOURCE)


if __name__ == "__main__":
    unittest.main()
