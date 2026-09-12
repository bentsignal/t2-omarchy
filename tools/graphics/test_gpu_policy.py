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
                self.assertEqual(m.desired_level('auto', ac, profile), 'high' if ac else 'low')

    def test_manual_override(self):
        self.assertEqual(m.desired_level('performance', False, 'power-saver'), 'high')
        self.assertEqual(m.desired_level('saver', True, 'performance'), 'low')
        with self.assertRaises(ValueError):
            m.desired_level('auto; command', True, 'performance')

    def test_manual_modes_survive_cable_and_cpu_profile_changes(self):
        for mode, level in [('performance', 'high'), ('saver', 'low')]:
            with tempfile.TemporaryDirectory() as temp, patch.object(m, 'power_source', return_value=True) as power, patch.object(m, 'profile', return_value='performance') as profile:
                control = Path(temp) / 'dpm'
                control.write_text('low')
                policy = m.Policy(lambda: control)
                policy.refresh(mode)
                for ac in (False, True, False):
                    power.return_value = ac
                    profile.return_value = 'power-saver' if ac else 'balanced'
                    result = policy.refresh()
                    self.assertEqual((result['mode'], result['level']), (mode, level))
                result = policy.refresh('auto')
                self.assertEqual((result['mode'], result['level']), ('auto', 'low'))
                power.return_value = True
                self.assertEqual(policy.refresh()['level'], 'high')

    def test_topology_failure_reports_error(self):
        with patch.object(m, 'power_source', return_value=True), patch.object(m, 'profile', return_value='performance'):
            def fail(): raise RuntimeError('Wrong display owner')
            result = m.Policy(fail).refresh()
            self.assertIn('Wrong display owner', result['error'])
            self.assertEqual(result['level'], 'unknown')
