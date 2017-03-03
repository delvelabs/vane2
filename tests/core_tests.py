# Vane 2.0: A web application vulnerability assessment tool.
# Copyright (C) 2017-  Delve Labs inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from unittest import TestCase
from unittest.mock import MagicMock, patch, call
from vane.core import Vane, OutputManager
from aiohttp.test_utils import make_mocked_coro, loop_context
from openwebvulndb.common.models import VulnerabilityList, Vulnerability, Meta
from collections import OrderedDict


class TestVane(TestCase):

    def setUp(self):
        with patch("vane.core.HammerTime", MagicMock()):
            self.vane = Vane()
        self.vane.output_manager = MagicMock()
        self.fake_meta = Meta(key="meta")

    def test_perform_action_raise_exception_if_no_url_and_action_is_scan(self):
        with self.assertRaises(ValueError):
            self.vane.perform_action(action="scan")

    def test_perform_action_flush_output(self):

        self.vane.perform_action(action="scan", url="test")

        self.vane.output_manager.flush.assert_called_once_with()

    def test_scan_target_output_database_version(self):
        self.skipTest("Must mock coroutines")
        self.vane.database = MagicMock()
        self.vane.database.get_version.return_value = "1.2"
        self.vane.hammertime.close = make_mocked_coro()

        with loop_context() as loop:
            with patch("vane.core.Vane.identify_target_version", make_mocked_coro()):
                loop.run_until_complete(self.vane.scan_target("test"))

                self.vane.output_manager.set_vuln_database_version.assert_called_once_with(
                    self.vane.database.get_version.return_value)

    def test_list_component_vulnerabilitites_call_list_vulnerabilities_for_each_component(self):
        components_version = {'plugin0': "1.2.3", 'theme0': "3.2.1", 'plugin1': "1.4.0", 'theme1': "6.9"}
        plugin0_vuln_list = VulnerabilityList(key="plugin0", producer="")
        plugin1_vuln_list = VulnerabilityList(key="plugin1", producer="")
        theme0_vuln_list = VulnerabilityList(key="theme0", producer="")
        theme1_vuln_list = VulnerabilityList(key="theme1", producer="")
        vuln_list_group = MagicMock()
        vuln_list_group.vulnerability_lists = [plugin0_vuln_list, plugin1_vuln_list, theme1_vuln_list, theme0_vuln_list]

        fake_list_vuln = MagicMock()

        with patch("vane.vulnerabilitylister.VulnerabilityLister.list_vulnerabilities", fake_list_vuln):
            self.vane.list_component_vulnerabilities(components_version, vuln_list_group)

            fake_list_vuln.assert_has_calls([call("1.2.3", plugin0_vuln_list), call("1.4.0", plugin1_vuln_list),
                                             call("3.2.1", theme0_vuln_list), call("6.9", theme1_vuln_list)],
                                            any_order=True)

    def test_list_component_vulnerabilitites_skip_component_with_no_vulnerability(self):
        components_version = {'plugin0': "1.2.3"}
        plugin1_vuln_list = VulnerabilityList(key="plugin1", producer="")
        vuln_list_group = MagicMock()
        vuln_list_group.vulnerability_lists = [plugin1_vuln_list]

        fake_list_vuln = MagicMock()

        with patch("vane.vulnerabilitylister.VulnerabilityLister.list_vulnerabilities", fake_list_vuln):
            self.vane.list_component_vulnerabilities(components_version, vuln_list_group)

            fake_list_vuln.assert_not_called()

    def test_list_component_vulnerabilitites_return_vulnerabilities_for_each_component(self):
        components_version = {'plugin0': "1.2.3", 'plugin1': "1.4.0"}
        plugin0_vuln_list = VulnerabilityList(key="plugin0", producer="", vulnerabilities=[Vulnerability(id="1234")])
        plugin1_vuln_list = VulnerabilityList(key="plugin1", producer="", vulnerabilities=[Vulnerability(id="2345")])
        vuln_list_group = MagicMock()
        vuln_list_group.vulnerability_lists = [plugin0_vuln_list, plugin1_vuln_list]

        def fake_list_vuln(self, version, vuln_list):
            return vuln_list.vulnerabilities

        with patch("vane.vulnerabilitylister.VulnerabilityLister.list_vulnerabilities", fake_list_vuln):
            vulns = self.vane.list_component_vulnerabilities(components_version, vuln_list_group)

            self.assertEqual(plugin0_vuln_list.vulnerabilities, vulns['plugin0'])
            self.assertEqual(plugin1_vuln_list.vulnerabilities, vulns['plugin1'])

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

    def test_output_manager_add_plugins_append_plugin_and_version_to_plugin_list(self):
        output_manager = OutputManager()
        output_manager.data["plugins"] = [{'key': "plugin0", 'version': "2.1"}]

        output_manager.add_plugin("plugin1", "4.7.2", self.fake_meta)

        self.assertEqual(output_manager.data["plugins"], [{'key': "plugin0", 'version': "2.1"},
                                                          {'key': "plugin1", 'version': "4.7.2",
                                                           "meta": {"key": "meta"}}])

    def test_output_manager_add_themes_append_theme_to_theme_list(self):
        output_manager = OutputManager()
        output_manager.data["themes"] = [{'key': "theme0", 'version': "1.2.3"}]

        output_manager.add_theme("theme1", "6.1", self.fake_meta)

        self.assertEqual(output_manager.data["themes"], [{'key': "theme0", 'version': "1.2.3"},
                                                         {'key': "theme1", 'version': "6.1", "meta": {"key": "meta"}}])

    def test_output_manager_add_vulnerability_add_vulnerability_to_vuln_list_of_key(self):
        output_manager = OutputManager()
        output_manager.add_plugin("plugins/my-plugin", "1.0", self.fake_meta)
        output_manager.add_theme("themes/my-theme", "2.0", self.fake_meta)

        output_manager.add_vulnerability("plugins/my-plugin", "my-plugin-vulnerability")
        output_manager.add_vulnerability("themes/my-theme", "my-theme-vuln")

        self.assertEqual(output_manager.data["plugins"][0]["vulnerabilities"][0], "my-plugin-vulnerability")
        self.assertEqual(output_manager.data["themes"][0]["vulnerabilities"][0], "my-theme-vuln")

    def test_output_manager_add_vulnerability_append_vulnerability_to_vulnerabilities_list_of_key(self):
        output_manager = OutputManager()
        output_manager.add_plugin("plugins/my-plugin", "1.0", self.fake_meta)
        output_manager.add_vulnerability("plugins/my-plugin", "vulnerability0")

        output_manager.add_vulnerability("plugins/my-plugin", "vulnerability1")

        self.assertEqual(output_manager.data["plugins"][0]["vulnerabilities"], ["vulnerability0", "vulnerability1"])

    def test_output_manager_get_component_dictionary_return_dictionary_of_component_with_key_in_data(self):
        output_manager = OutputManager()
        output_manager.add_plugin("plugins/plugin0", "2.0", self.fake_meta)
        output_manager.add_plugin("plugins/plugin1", "1.5", self.fake_meta)
        output_manager.add_theme("themes/theme0", "4.5", self.fake_meta)
        output_manager.add_theme("themes/theme1", "3.2.1", self.fake_meta)
        output_manager.set_wordpress_version("4.2.2", self.fake_meta)

        plugin0 = output_manager._get_component_dictionary("plugins/plugin0")
        plugin1 = output_manager._get_component_dictionary("plugins/plugin1")
        theme0 = output_manager._get_component_dictionary("themes/theme0")
        theme1 = output_manager._get_component_dictionary("themes/theme1")
        wordpress = output_manager._get_component_dictionary("wordpress")

        self.assertEqual(plugin0, {"key": "plugins/plugin0", "version": "2.0", "meta": {"key": "meta"}})
        self.assertEqual(plugin1, {"key": "plugins/plugin1", "version": "1.5", "meta": {"key": "meta"}})
        self.assertEqual(theme0, {"key": "themes/theme0", "version": "4.5", "meta": {"key": "meta"}})
        self.assertEqual(theme1, {"key": "themes/theme1", "version": "3.2.1", "meta": {"key": "meta"}})
        self.assertEqual(wordpress, {"version": "4.2.2", "meta": {"key": "meta"}})
