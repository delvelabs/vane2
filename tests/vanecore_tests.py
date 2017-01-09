from unittest import TestCase
from unittest.mock import MagicMock
from vane.vanecore import Vane


class TestVane(TestCase):

    def setUp(self):
        self.vane = Vane()
        self.vane.database = MagicMock()
        self.vane.database.get_version.return_value = "1.2"

    def test_perform_action_raise_exception_if_no_url(self):
        with self.assertRaises(ValueError):
            self.vane.perfom_action()

    def test_perform_action_print_json_output(self):
        self.vane.hammertime = MagicMock()
        self.vane.output_manager = MagicMock()

        self.vane.perfom_action(url="test")

        self.vane.output_manager.json.assert_called_once_with(self.vane.json_output)

    def test_log_message_add_message_to_general_log_in_json_output(self):
        self.vane._log_message("test")

        self.assertEqual(self.vane.json_output["general_log"], ["test"])

    def test_perform_action_logs_operation_in_json_output(self):
        self.vane.perfom_action(url="test")

        self.assertEqual(self.vane.json_output["general_log"], ["sending request to test", "request failed"])

    def test_perform_action_logs_wordpress_version_in_json_output_if_action_is_complete_scan(self):
        self.vane.get_wordpress_version = MagicMock()
        self.vane.get_wordpress_version.return_value = "Wordpress 1.2"

        self.vane.perfom_action(action="complete_scan", url="website_with_wordpress")

        self.assertEqual(self.vane.json_output["wordpress_version"], self.vane.get_wordpress_version.return_value)

    def test_perform_action_logs_plugins_in_json_output_if_action_is_complete_scan(self):
        self.vane.list_plugins = MagicMock()
        self.vane.list_plugins.return_value = ["plugin0", "plugin1"]

        self.vane.perfom_action(action="complete_scan", url="website_with_wordpress")

        self.assertEqual(self.vane.json_output["plugins"], self.vane.list_plugins.return_value)

    def test_perform_action_logs_themes_in_json_output_if_action_is_complete_scan(self):
        self.vane.list_themes = MagicMock()
        self.vane.list_themes.return_value = ["theme0", "theme1"]

        self.vane.perfom_action(action="complete_scan", url="website_with_wordpress")

        self.assertEqual(self.vane.json_output["themes"], self.vane.list_themes.return_value)

    def test_perform_action_logs_vulnerabilities_in_json_output_if_action_is_complete_scan(self):
        self.vane.find_vulnerabilities = MagicMock()
        self.vane.find_vulnerabilities.return_value = [{"vuln0": {}, "vuln1": {}}]

        self.vane.perfom_action(action="complete_scan", url="website_with_wordpress")

        self.assertEqual(self.vane.json_output["vulnerabilities"], self.vane.find_vulnerabilities.return_value)

    def test_perform_action_logs_database_version(self):
        self.vane.perfom_action(action="complete_scan", url="test")

        self.assertEqual(self.vane.json_output["database_version"], self.vane.database.get_version.return_value)
