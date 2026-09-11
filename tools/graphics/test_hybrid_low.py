import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('hybrid', Path(__file__).with_name('t2-hybrid-low.py'))
hybrid = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hybrid)


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.put('class/dmi/id/product_name', 'MacBookPro16,1\n')
        for address, vendor, device, driver in (
            ('0000:00:02.0', '0x8086', '0x3e9b', 'i915'),
            ('0000:03:00.0', '0x1002', '0x7340', 'amdgpu'),
        ):
            base = f'bus/pci/devices/{address}'
            self.put(base + '/vendor', vendor)
            self.put(base + '/device', device)
            target = self.root / 'bus/pci/drivers' / driver
            target.mkdir(parents=True)
            (self.root / base / 'driver').symlink_to(target)
        self.mux = 'kernel/debug/vgaswitcheroo/switch'
        self.put(self.mux, '0:DIS-Audio: :DynOff:0000:03:00.1\n1:IGD:+:Pwr:0000:00:02.0\n2:DIS: :Pwr:0000:03:00.0\n')
        self.panel = 'bus/pci/devices/0000:00:02.0/drm/card7/card7-eDP-1/status'
        self.put(self.panel, 'connected\n')
        self.put('bus/pci/devices/0000:03:00.0/power_state', 'D0\n')

    def put(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)

    def check(self, cmdline='rw apple_gmux.force_igd=1 t2.graphics=hybrid'):
        return hybrid.check_topology(self.root, cmdline)

    def test_intel_primary_accepts_dynamic_card_number(self):
        self.assertEqual(self.check().name, 'power_dpm_force_performance_level')

    def test_default_boot_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'not selected'):
            self.check('rw apple_gmux.force_igd=1')

    def test_wrong_model_refused(self):
        self.put('class/dmi/id/product_name', 'MacBookPro15,1')
        with self.assertRaisesRegex(RuntimeError, 'model'):
            self.check()

    def test_wrong_gpu_refused(self):
        self.put('bus/pci/devices/0000:03:00.0/device', '0xffff')
        with self.assertRaisesRegex(RuntimeError, 'identity'):
            self.check()

    def test_amd_display_owner_refused(self):
        self.put(self.mux, '1:IGD: :Pwr:0000:00:02.0\n2:DIS:+:Pwr:0000:03:00.0\n')
        with self.assertRaisesRegex(RuntimeError, 'active powered'):
            self.check()

    def test_missing_panel_refused(self):
        self.put(self.panel, 'disconnected')
        with self.assertRaisesRegex(RuntimeError, 'internal panel'):
            self.check()

    def test_powered_off_amd_refused(self):
        self.put('bus/pci/devices/0000:03:00.0/power_state', 'D3hot')
        with self.assertRaisesRegex(RuntimeError, 'not powered'):
            self.check()


if __name__ == '__main__':
    unittest.main()
