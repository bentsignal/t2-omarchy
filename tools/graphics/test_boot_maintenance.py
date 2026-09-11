import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('boot', Path(__file__).with_name('maintain-boot.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class BootMaintenanceTests(unittest.TestCase):
    def fixture(self):
        return (f'default_entry: 1\n/T2 Intel-primary hybrid test\npath: {m.IMAGE}#old\ncmdline: rw old=1\n\n'
                f'/+Omarchy\n  //linux-t2\n  comment: kernel-id=linux-t2 \n  path: {m.IMAGE}#abcd\n  cmdline: rw resume_offset=456\n'
                f'  //linux-t2 (Intel graphics test)\n  path: {m.IMAGE}#1234\n  cmdline: rw resume_offset=123 apple_gmux.force_igd=1\n'
                '  //Snapshots\n   ///old\n    ////linux-t2\n    path: boot():/history/old.efi#1234\n    cmdline: snapshot=1\n')

    def test_refresh_names_hashes_and_current_boot_parameters(self):
        text = m.update_config(self.fixture(), 'abcd')
        self.assertTrue(text.startswith('default_entry: 1\n/T2 Linux — Hybrid\n'))
        self.assertIn('//T2 Linux — GPU disabled', text)
        self.assertIn('//T2 Linux — AMD graphics', text)
        self.assertNotIn('resume_offset=123', text)
        self.assertIn('path: boot():/history/old.efi#1234', text)
        self.assertEqual(m.update_config(text, 'abcd'), text)

    def test_unexplained_image_change_refused(self):
        with self.assertRaises(RuntimeError): m.update_config(self.fixture(), 'ffff')

    def test_missing_hybrid_refused(self):
        with self.assertRaises(RuntimeError): m.update_config(self.fixture().replace('/T2 Intel-primary hybrid test', '/Other'), 'abcd')
