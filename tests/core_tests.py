from unittest import TestCase
from unittest.mock import MagicMock, patch
from vane.core import Vane, OutputManager
from aiohttp.test_utils import make_mocked_coro, loop_context


class TestVane(TestCase):

    def setUp(self):
        with patch("vane.core.HammerTime", MagicMock()):
            self.vane = Vane()
        self.vane.output_manager = MagicMock()

    def test_perform_action_raise_exception_if_no_url_and_action_is_scan(self):
        with self.assertRaises(ValueError):
            self.vane.perfom_action(action="scan")

    def test_perform_action_flush_output(self):

        self.vane.perfom_action(action="scan", url="test")

        self.vane.output_manager.flush.assert_called_once_with()


    def test_scan_target_output_database_version(self):
        self.vane.database = MagicMock()
        self.vane.database.get_version.return_value = "1.2"
        self.vane.hammertime.close = make_mocked_coro()

        with loop_context() as loop:
            with patch("vane.core.Vane.identify_target_version", make_mocked_coro()):
                loop.run_until_complete(self.vane.scan_target("test"))

                self.vane.output_manager.set_vuln_database_version.assert_called_once_with(
                    self.vane.database.get_version.return_value)

    def test_output_manager_add_data_create_key_if_key_not_in_data(self):
        output_manager = OutputManager()

        output_manager._add_data("new_key", "value")

        self.assertIn("new_key", output_manager.data)

    def test_output_manager_add_data_put_data_in_list(self):
        output_manager = OutputManager()

        output_manager._add_data("key", "value")

        self.assertEqual(output_manager.data["key"], ["value"])

    def test_output_manager_add_data_extends_existing_list_if_data_is_list(self):
        output_manager = OutputManager()
        key = "key"
        output_manager._add_data(key, "value0")

        output_manager._add_data(key, ["value1", "value2"])

        self.assertEqual(output_manager.data["key"], ["value0", "value1", "value2"])

    def test_output_manager_log_message_append_message_to_existing_log(self):
        output_manager = OutputManager()
        output_manager.log_message("message0")

        output_manager.log_message("message1")

        self.assertEqual(output_manager.data["general_log"], ["message0", "message1"])

    def test_output_manager_add_plugins_append_plugin_to_plugin_list(self):
        output_manager = OutputManager()
        output_manager.data["plugins"] = ["plugin0"]

        output_manager.add_plugin("plugin1")

        self.assertEqual(output_manager.data["plugins"], ["plugin0", "plugin1"])

    def test_output_manager_add_themes_append_theme_to_theme_list(self):
        output_manager = OutputManager()
        output_manager.data["themes"] = ["theme0"]

        output_manager.add_theme("theme1")

        self.assertEqual(output_manager.data["themes"], ["theme0", "theme1"])

    def test_output_manager_add_vulnerability_append_vulnerability_to_vulnerabilities_list(self):
        output_manager = OutputManager()
        output_manager.data["vulnerabilities"] = ["vulnerability0"]

        output_manager.add_vulnerability("vulnerability1")

        self.assertEqual(output_manager.data["vulnerabilities"], ["vulnerability0", "vulnerability1"])
