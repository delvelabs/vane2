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
from vane.core import Vane
from aiohttp.test_utils import make_mocked_coro, loop_context
import asyncio
from openwebvulndb.common.models import VulnerabilityList, Vulnerability
from hammertime.http import Entry
from hammertime.ruleset import HammerTimeException
from vane.outputmanager import OutputManager


@patch("vane.core.load_model_from_file", MagicMock(return_value=(MagicMock(), "errors")))
class TestVane(TestCase):

    def setUp(self):
        with patch("vane.core.HammerTime", MagicMock()):
            self.vane = Vane()
        self.vane.output_manager = MagicMock()

    def test_perform_action_raise_exception_if_no_url_and_action_is_scan(self):
        with self.assertRaises(ValueError):
            self.vane.perform_action(action="scan")

    def test_perform_action_flush_output(self):
        self.vane.perform_action(action="scan", url="test")

        self.vane.output_manager.flush.assert_called_once_with()

    def test_perform_action_call_set_proxy_if_proxy_is_not_none(self):
        self.vane.set_proxy = MagicMock()

        self.vane.perform_action(action="scan", url="test", proxy="http://127.0.0.1:8080")

        self.vane.set_proxy.assert_called_once_with("http://127.0.0.1:8080")

    def test_perform_action_dont_call_set_proxy_if_proxy_is_none(self):
        self.vane.set_proxy = MagicMock()

        self.vane.perform_action(action="scan", url="test")

        self.vane.set_proxy.assert_not_called()

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

    def test_scan_target_abort_after_version_identification_if_identification_fails(self):
        self.vane.active_plugin_enumeration = make_mocked_coro()
        self.vane.active_theme_enumeration = make_mocked_coro()
        self.vane.hammertime.close = make_mocked_coro()
        self.vane.identify_target_version = make_mocked_coro(raise_exception=
                                                             ValueError("target is not a valid Wordpress site."))

        with loop_context() as loop:
            loop.run_until_complete(self.vane.scan_target("http://www.test.com/", True, True))

        self.vane.active_plugin_enumeration.assert_not_called()
        self.vane.active_theme_enumeration.assert_not_called()
        self.vane.hammertime.close.assert_called_once_with()

    def test_scan_target_log_message_if_scan_aborted(self):
        self.vane.hammertime.close = make_mocked_coro()
        exception = ValueError("target is not a valid Wordpress site.")
        self.vane.identify_target_version = make_mocked_coro(raise_exception=exception)

        with loop_context() as loop:
            loop.run_until_complete(self.vane.scan_target("http://www.test.com/", True, True))

        self.vane.output_manager.log_message.assert_any_call(str(exception))

    def test_scan_target_abort_if_target_is_not_valid_url(self):
        self.vane.active_plugin_enumeration = make_mocked_coro()
        self.vane.active_theme_enumeration = make_mocked_coro()
        self.vane.hammertime.close = make_mocked_coro()
        self.vane.identify_target_version = make_mocked_coro()

        with loop_context() as loop:
            loop.run_until_complete(self.vane.scan_target("www.test.com", True, True))

        self.vane.active_plugin_enumeration.assert_not_called()
        self.vane.active_theme_enumeration.assert_not_called()
        self.vane.identify_target_version.assert_not_called()
        self.vane.hammertime.close.assert_called_once_with()

    def test_identify_target_version_raise_value_error_if_version_identification_return_no_fetched_files(self):
        fake_load = MagicMock()
        fake_load.return_value = "data", "errors"
        fake_fetcher = MagicMock()
        fake_fetcher.request_files = make_mocked_coro(return_value=("key", []))
        fake_fetcher_factory = MagicMock()
        fake_fetcher_factory.return_value = fake_fetcher
        with patch("vane.core.load_model_from_file", fake_load):
            with patch("vane.core.FileFetcher", fake_fetcher_factory):
                with loop_context() as loop:
                    with self.assertRaises(ValueError):
                        loop.run_until_complete(self.vane.identify_target_version("invalid url", "input path"))

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

    def test_passive_plugin_enumeration_return_dict_with_plugins_key_and_version(self):
        fake_plugin_finder = MagicMock()
        fake_plugin_finder.list_plugins.return_value = {"plugins/wp-postratings": None, "plugins/disqus-comment-system":
                                                        "1.0.2", "plugins/cyclone-slider-2": "2.9.1"}
        fake_plugin_finder_factory = MagicMock()
        fake_plugin_finder_factory.return_value = fake_plugin_finder

        with patch("vane.core.PassivePluginsFinder", fake_plugin_finder_factory):
            plugins = self.vane.passive_plugin_enumeration("html_page", None)

            self.assertEqual(plugins["plugins/disqus-comment-system"], "1.0.2")
            self.assertIsNone(plugins["plugins/wp-postratings"])
            self.assertEqual(plugins["plugins/cyclone-slider-2"], "2.9.1")

    def test_plugin_enumeration_merge_active_and_passive_detection_results(self):
        self.vane.active_plugin_enumeration = make_mocked_coro(return_value={"plugins/plugin0": "1.2",
                                                                             "plugins/plugin1": "3.2.1"})
        self.vane.passive_plugin_enumeration = MagicMock(return_value={"plugins/plugin2" : "4.3.1",
                                                                       "plugins/plugin1": None})
        self.vane.hammertime.request = make_mocked_coro(return_value=MagicMock())

        with loop_context() as loop:
            plugins_version = loop.run_until_complete(self.vane.plugin_enumeration("target", True, True, "path"))

            self.assertEqual(plugins_version, {"plugins/plugin0": "1.2", "plugins/plugin1": "3.2.1",
                                               "plugins/plugin2": "4.3.1"})

    def test_plugin_enumeration_overwrite_version_found_during_active_scan_with_passive_detection_results_if_not_none(self):
        self.vane.active_plugin_enumeration = make_mocked_coro(return_value={"plugins/plugin0": None,
                                                                             "plugins/plugin1": "3.2.1",
                                                                             "plugins/plugin2": "1.2.3"})
        self.vane.passive_plugin_enumeration = MagicMock(return_value={"plugins/plugin0": "4.3.1",
                                                                       "plugins/plugin1": None,
                                                                       "plugins/plugin2": "1.2.4"})
        self.vane.hammertime.request = make_mocked_coro(return_value=MagicMock())

        self.vane.output_manager = OutputManager()

        with loop_context() as loop:
            plugins_version = loop.run_until_complete(self.vane.plugin_enumeration("target", True, True, "path"))

            self.assertEqual(plugins_version, {"plugins/plugin0": "4.3.1", "plugins/plugin1": "3.2.1",
                                               "plugins/plugin2": "1.2.4"})

            plugins_data = self.vane.output_manager.data["plugins"]
            plugin0_data = [plugin_dict for plugin_dict in plugins_data if plugin_dict["key"] == "plugins/plugin0"][0]
            plugin2_data = [plugin_dict for plugin_dict in plugins_data if plugin_dict["key"] == "plugins/plugin2"][0]
            self.assertEqual(plugin0_data["version"], "4.3.1")
            self.assertEqual(plugin2_data["version"], "1.2.4")

    def test_plugin_enumeration_only_log_plugins_found_in_passive_scan_not_log_by_active_scan(self):
        self.vane.active_plugin_enumeration = make_mocked_coro(return_value={"plugins/plugin0": "1.2",
                                                                             "plugins/plugin1": "3.2.1"})
        self.vane.passive_plugin_enumeration = MagicMock(return_value={"plugins/plugin2": None,
                                                                       "plugins/plugin1": None})
        self.vane.hammertime.request = make_mocked_coro(return_value=MagicMock())

        with loop_context() as loop:
            loop.run_until_complete(self.vane.plugin_enumeration("target", True, True, "path"))

            call_args = self.vane.output_manager.add_plugin.call_args
            self.assertEqual(len(self.vane.output_manager.add_plugin.mock_calls), 1)
            self.assertEqual(call_args[0][0], "plugins/plugin2")
            self.assertIsNone(call_args[0][1])

    def test_passive_theme_enumeration_return_set_of_theme_keys(self):
        fake_theme_finder = MagicMock()
        fake_theme_finder.list_themes.return_value = {"themes/twentyseventeen", "themes/twentysixteen"}

        fake_theme_finder_factory = MagicMock()
        fake_theme_finder_factory.return_value = fake_theme_finder

        with patch("vane.core.PassiveThemesFinder", fake_theme_finder_factory):
            themes = self.vane.passive_theme_enumeration("html_page", None)

            self.assertIn("themes/twentyseventeen", themes)
            self.assertIn("themes/twentysixteen", themes)

    def test_theme_enumeration_merge_active_and_passive_detection_results(self):
        self.vane.active_theme_enumeration = make_mocked_coro(return_value={"themes/theme0": "1.2",
                                                                             "themes/theme1": "3.2.1"})
        self.vane.passive_theme_enumeration = MagicMock(return_value={"themes/theme2", "themes/theme1"})
        self.vane.hammertime.request = make_mocked_coro(return_value=MagicMock())

        with loop_context() as loop:
            themes_version = loop.run_until_complete(self.vane.theme_enumeration("target", True, True, "path"))

            self.assertEqual(themes_version, {"themes/theme0": "1.2", "themes/theme1": "3.2.1",
                                              "themes/theme2": None})

    def test_theme_enumeration_log_theme_found_in_passive_scan_but_not_in_active_scan(self):
        self.vane.active_theme_enumeration = make_mocked_coro(return_value={"themes/theme0": "1.2",
                                                                            "themes/theme1": "3.2.1"})
        self.vane.passive_theme_enumeration = MagicMock(return_value=["themes/theme2", "themes/theme1"])
        self.vane.hammertime.request = make_mocked_coro(return_value=MagicMock())

        with loop_context() as loop:
            loop.run_until_complete(self.vane.theme_enumeration("target", True, True, "path"))

            call_args = self.vane.output_manager.add_theme.call_args
            self.assertEqual(len(self.vane.output_manager.add_theme.mock_calls), 1)
            self.assertEqual(call_args[0][0], "themes/theme2")
            self.assertIsNone(call_args[0][1])

    def test_set_proxy_set_hammertime_proxy(self):
        self.vane.set_proxy("http://127.0.0.1:8080")

        self.vane.hammertime.set_proxy.assert_called_once_with("http://127.0.0.1:8080")

    def test_scan_target_only_use_passive_detection_if_passive_parameter_is_true(self):
        self.vane.identify_target_version = make_mocked_coro()
        self.vane.active_plugin_enumeration = make_mocked_coro()
        self.vane.passive_plugin_enumeration = MagicMock(return_value={})
        self.vane.passive_theme_enumeration = MagicMock(return_value=[])
        self.vane.active_theme_enumeration = make_mocked_coro()
        self.vane.list_component_vulnerabilities = MagicMock()
        self.vane.hammertime.request = make_mocked_coro(return_value=MagicMock())
        self.vane.hammertime.close = make_mocked_coro()
        self.vane._load_meta_list = MagicMock(return_value=("meta_list", "errors"))

        with loop_context() as loop:
            loop.run_until_complete(self.vane.scan_target("http://www.unit.test/", True, True, passive_only=True))

            self.vane.active_theme_enumeration.assert_not_called()
            self.vane.active_plugin_enumeration.assert_not_called()
            self.assertEqual(len(self.vane.passive_theme_enumeration.mock_calls), 1)
            self.assertEqual(len(self.vane.passive_plugin_enumeration.mock_calls), 1)

    def test_request_target_home_page_make_hammertime_request_for_target_url(self):
        with loop_context() as loop:
            target_url = "http://www.example.com/"
            self.vane.hammertime.request = make_mocked_coro(return_value=Entry.create(target_url))

            loop.run_until_complete(self.vane._request_target_home_page(target_url))

            self.vane.hammertime.request.assert_called_once_with(target_url)

    def test_request_target_home_page_return_hammertime_response_for_request(self):
        target_url = "http://www.example.com/"
        entry = Entry.create(target_url, response="response")
        with loop_context() as loop:
            self.vane.hammertime.request = make_mocked_coro(return_value=entry)

            response = loop.run_until_complete(self.vane._request_target_home_page(target_url))

            self.assertEqual(response, "response")

    def test_request_target_home_page_raises_hammertime_exception(self):
        target_url = "http://www.example.com/"
        with loop_context() as loop:
            self.vane.hammertime.request = make_mocked_coro(raise_exception=HammerTimeException())

            with self.assertRaises(HammerTimeException):
                loop.run_until_complete(self.vane._request_target_home_page(target_url))
