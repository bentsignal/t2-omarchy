import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('default', Path(__file__).with_name('set-hybrid-default.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class DefaultTests(unittest.TestCase):
    fixture = ('default_entry: 2\n/+Omarchy\n  //linux-t2\n  protocol: efi\n'
               '# BEGIN T2 HYBRID TRIAL\n/T2 Intel-primary hybrid test\n'
               'protocol: efi\ncmdline: rw apple_gmux.force_igd=1 t2.graphics=hybrid\n'
               '# END T2 HYBRID TRIAL\n\n/EFI fallback\n')

    def test_selects_first_and_keeps_recovery(self):
        result = module.select_hybrid(self.fixture)
        self.assertIn('default_entry: 1\n', result)
        self.assertLess(result.index('/T2 Intel-primary'), result.index('/+Omarchy'))
        self.assertIn('/+Omarchy\n  //linux-t2\n  protocol: efi\n', result)
        self.assertIn('/EFI fallback\n', result)
        self.assertEqual(result, module.select_hybrid(result))

    def test_missing_marker_refused(self):
        with self.assertRaises(RuntimeError):
            module.select_hybrid(self.fixture.replace('t2.graphics=hybrid', ''))

    def test_missing_default_refused(self):
        with self.assertRaises(RuntimeError):
            module.select_hybrid(self.fixture.replace('default_entry: 2\n', ''))


if __name__ == '__main__':
    unittest.main()
