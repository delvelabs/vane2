from unittest import TestCase
from unittest.mock import MagicMock
from vane.vanecore import Vane


class TestVane(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.vane = Vane()

    def setUp(self):
        self.vane.output_manager = MagicMock()

    def test_perform_action_raise_exception_if_no_url(self):
        with self.assertRaises(ValueError):
            self.vane.perfom_action()

    def test_perform_action_flush_output(self):
        hammertime = self.vane.hammertime
        self.vane.hammertime = MagicMock()

        self.vane.perfom_action(url="test")

        self.vane.output_manager.flush.assert_called_once_with()

        self.vane.hammertime = hammertime

    def test_perform_action_output_target_information_if_action_is_complete_scan(self):
        self.vane.perfom_action(action="complete_scan", url="website_with_wordpress")

        self.assertTrue(self.vane.output_manager.set_wordpress_version.called)
        self.assertTrue(self.vane.output_manager.set_plugins.called)
        self.assertTrue(self.vane.output_manager.set_themes.called)
        self.assertTrue(self.vane.output_manager.set_vulnerabilities.called)

    def test_perform_action_output_database_version(self):
        self.vane.database = MagicMock()
        self.vane.database.get_version.return_value = "1.2"

        self.vane.perfom_action(action="complete_scan", url="test")

        self.vane.output_manager.set_vuln_database_version.assert_called_once_with(self.vane.database.get_version.return_value)
