import contextlib
import io
import unittest
from unittest.mock import patch

import jc2mp_launch as launch


class GuiPatchTests(unittest.TestCase):
    def setUp(self):
        self.addresses = [launch.GAME_BASE + rva for rva in launch.GUI_CHECK_RVAS]
        self.reset_memory()

    def reset_memory(self):
        self.memory = {address: launch.GUI_CHECK_ORIGINAL for address in self.addresses}

    def apply(self, write=None):
        if write is None:
            write = lambda pid, address, data: self.memory.__setitem__(address, data)
        with (
            patch.object(launch, "read_memory", side_effect=lambda pid, address, size: self.memory[address][:size]),
            patch.object(launch, "write_memory", side_effect=write),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            launch.patch_gui_checks(123)

    def test_all_three_registration_checks_are_patched(self):
        self.assertEqual(launch.GUI_CHECK_RVAS, (0x412A0, 0x45340, 0x477F0))
        self.apply()
        replacement = bytes.fromhex("b0 01 c3 90 90 90")
        self.assertEqual(len(replacement), len(launch.GUI_CHECK_ORIGINAL))
        for address in self.addresses:
            self.assertEqual(self.memory[address], replacement)

    def test_any_mismatch_prevents_all_writes(self):
        for address in self.addresses:
            with self.subTest(address=hex(address)):
                self.reset_memory()
                self.memory[address] = b"\xcc" * len(launch.GUI_CHECK_ORIGINAL)
                with (
                    patch.object(launch, "read_memory", side_effect=lambda pid, at, size: self.memory[at][:size]),
                    patch.object(launch, "write_memory") as write,
                ):
                    with self.assertRaisesRegex(ValueError, "unsupported GUI registration check"):
                        launch.patch_gui_checks(123)
                    write.assert_not_called()

    def test_failed_write_at_any_site_is_reported(self):
        for failed_address in self.addresses:
            with self.subTest(address=hex(failed_address)):
                self.reset_memory()
                written = []

                def write(pid, address, data):
                    written.append(address)
                    if address != failed_address:
                        self.memory[address] = data

                with self.assertRaisesRegex(ValueError, f"verification failed at {failed_address:#x}"):
                    self.apply(write=write)
                self.assertEqual(written, self.addresses[:self.addresses.index(failed_address) + 1])


if __name__ == "__main__":
    unittest.main()
