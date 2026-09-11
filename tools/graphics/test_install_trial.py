import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('installer', Path(__file__).with_name('install-trial.py'))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class BootEntryTests(unittest.TestCase):
    fixture = ('  //linux-t2 (Intel graphics test)\n'
               '  protocol: efi\n  path: boot():/EFI/Linux/test.efi#hash\n'
               '  cmdline: rw apple_gmux.force_igd=1\n\n'
               '     //Snapshots\n     ////linux-t2\n'
               '     path: snapshot.efi\n/EFI fallback\n')

    def test_preserves_image_hash_and_cmdline(self):
        result = installer.trial_block(self.fixture)
        self.assertIn('path: boot():/EFI/Linux/test.efi#hash\n', result)
        self.assertIn('cmdline: rw apple_gmux.force_igd=1 t2.graphics=hybrid\n', result)
        self.assertNotIn('snapshot.efi', result)

    def test_missing_entry_refused(self):
        with self.assertRaises(RuntimeError):
            installer.trial_block('/Some other boot\n')

    def test_missing_intel_parameter_refused(self):
        with self.assertRaises(RuntimeError):
            installer.trial_block(self.fixture.replace('apple_gmux.force_igd=1', ''))

    def test_duplicate_path_refused(self):
        with self.assertRaises(RuntimeError):
            installer.trial_block(self.fixture.replace('  protocol: efi', '  path: other\n  protocol: efi'))


if __name__ == '__main__':
    unittest.main()
