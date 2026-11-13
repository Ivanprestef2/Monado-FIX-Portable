"""Source-level checks for the opt-in --game option (RecompLauncher): the old positional form must stay."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MAIN_BOOT = (ROOT / "runtime/host/main_boot.c").read_text(encoding="utf-8")


class GameOption(unittest.TestCase):
    def test_game_option_is_read_only_when_it_is_the_first_argument(self):
        self.assertIn('argc >= 2 && !strcmp(argv[1], "--game")', MAIN_BOOT)

    def test_positional_dump_folder_still_works(self):
        self.assertIn("int first = game_opt ? 2 : 1;", MAIN_BOOT)
        self.assertIn("const char *root = argv[first];", MAIN_BOOT)

    def test_working_folder_only_changes_with_the_game_option(self):
        self.assertIn("if (game_opt && enter_install_dir(", MAIN_BOOT)
        self.assertEqual(MAIN_BOOT.count("SetCurrentDirectoryA"), 1)


if __name__ == "__main__":
    unittest.main()
