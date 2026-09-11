import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('policy', Path(__file__).with_name('t2-gpu-policy.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class PolicyTests(unittest.TestCase):
    def test_automatic_performance_only_on_ac(self):
        for ac in (True, False):
            for profile in ('performance', 'balanced', 'power-saver', 'unknown'):
                self.assertEqual(m.desired_level('auto', ac, profile), 'high' if ac and profile == 'performance' else 'low')

    def test_manual_override(self):
        self.assertEqual(m.desired_level('performance', False, 'power-saver'), 'high')
        self.assertEqual(m.desired_level('saver', True, 'performance'), 'low')
        with self.assertRaises(ValueError):
            m.desired_level('auto; command', True, 'performance')

    def test_unplug_resets_override_and_lowers_gpu(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(m, 'power_source', return_value=True) as power, patch.object(m, 'profile', return_value='performance'):
            control = Path(temp) / 'dpm'
            control.write_text('low')
            policy = m.Policy(lambda: control)
            self.assertEqual(policy.refresh('performance')['level'], 'high')
            power.return_value = False
            result = policy.refresh()
            self.assertEqual((result['mode'], result['level']), ('auto', 'low'))
            self.assertEqual(policy.refresh('performance')['level'], 'high')

    def test_topology_failure_reports_error(self):
        with patch.object(m, 'power_source', return_value=True), patch.object(m, 'profile', return_value='performance'):
            def fail(): raise RuntimeError('Wrong display owner')
            result = m.Policy(fail).refresh()
            self.assertIn('Wrong display owner', result['error'])
            self.assertEqual(result['level'], 'unknown')
