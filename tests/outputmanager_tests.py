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
from unittest.mock import MagicMock, patch

from vane.outputmanager import OutputManager
from openwebvulndb.common.models import Meta

import termcolor


class TestOutputManager(TestCase):

    def setUp(self):
        self.output_manager = OutputManager()
        self.fake_meta = Meta(key="meta", name="Name", url="example.com")

    def test_add_data_create_key_if_key_not_in_data(self):
        self.output_manager._add_data("new_key", "value")

        self.assertIn("new_key", self.output_manager.data)

    def test_add_data_put_data_in_list(self):
        self.output_manager._add_data("key", "value")

        self.assertEqual(self.output_manager.data["key"], ["value"])

    def test_add_data_extends_existing_list_if_data_is_list(self):
        key = "key"
        self.output_manager._add_data(key, "value0")

        self.output_manager._add_data(key, ["value1", "value2"])

        self.assertEqual(self.output_manager.data["key"], ["value0", "value1", "value2"])

    def test_log_message_append_message_to_existing_log(self):
        self.output_manager.log_message("message0")

        self.output_manager.log_message("message1")

        self.assertEqual(self.output_manager.data["general_log"], ["message0", "message1"])

    def test_add_plugins_append_plugin_and_version_to_plugin_list(self):
        self.output_manager.data["plugins"] = [{'key': "plugin0", 'version': "2.1"}]

        self.output_manager.add_plugin("plugin1", "4.7.2", None)

        self.assertEqual(self.output_manager.data["plugins"], [{'key': "plugin0", 'version': "2.1"},
                                                               {'key': "plugin1", 'version': "4.7.2"}])

    def test_add_themes_append_theme_to_theme_list(self):
        output_manager = OutputManager()
        output_manager.data["themes"] = [{'key': "theme0", 'version': "1.2.3"}]

        output_manager.add_theme("theme1", "6.1", None)

        self.assertEqual(output_manager.data["themes"], [{'key': "theme0", 'version': "1.2.3"},
                                                         {'key': "theme1", 'version': "6.1"}])

    def test_add_component_merge_meta_name_and_url_with_component(self):
        self.output_manager._add_component("plugins", "plugins/my-plugin", "1.2", self.fake_meta)
        self.output_manager._add_component("themes", "themes/my-theme", "2.0", self.fake_meta)

        self.assertEqual(self.output_manager.data["plugins"], [{"key": "plugins/my-plugin", "version": "1.2",
                                                                "name": self.fake_meta.name, "url": self.fake_meta.url}])
        self.assertEqual(self.output_manager.data["themes"], [{"key": "themes/my-theme", "version": "2.0",
                                                               "name": self.fake_meta.name, "url": self.fake_meta.url}])

    def test_add_vulnerability_add_vulnerability_to_vuln_list_of_key(self):
        self.output_manager.add_plugin("plugins/my-plugin", "1.0", None)
        self.output_manager.add_theme("themes/my-theme", "2.0", None)

        self.output_manager.add_vulnerability("plugins/my-plugin", "my-plugin-vulnerability")
        self.output_manager.add_vulnerability("themes/my-theme", "my-theme-vuln")

        self.assertEqual(self.output_manager.data["plugins"][0]["vulnerabilities"][0], "my-plugin-vulnerability")
        self.assertEqual(self.output_manager.data["themes"][0]["vulnerabilities"][0], "my-theme-vuln")

    def test_add_vulnerability_append_vulnerability_to_vulnerabilities_list_of_key(self):
        self.output_manager.add_plugin("plugins/my-plugin", "1.0", None)
        self.output_manager.add_vulnerability("plugins/my-plugin", "vulnerability0")

        self.output_manager.add_vulnerability("plugins/my-plugin", "vulnerability1")

        self.assertEqual(self.output_manager.data["plugins"][0]["vulnerabilities"], ["vulnerability0", "vulnerability1"])

    def test_get_component_dictionary_return_dictionary_of_component_with_key_in_data(self):
        self.output_manager.add_plugin("plugins/plugin0", "2.0", None)
        self.output_manager.add_plugin("plugins/plugin1", "1.5", None)
        self.output_manager.add_theme("themes/theme0", "4.5", None)
        self.output_manager.add_theme("themes/theme1", "3.2.1", None)
        self.output_manager.set_wordpress_version("4.2.2", None)

        plugin0 = self.output_manager._get_component_dictionary("plugins/plugin0")
        plugin1 = self.output_manager._get_component_dictionary("plugins/plugin1")
        theme0 = self.output_manager._get_component_dictionary("themes/theme0")
        theme1 = self.output_manager._get_component_dictionary("themes/theme1")
        wordpress = self.output_manager._get_component_dictionary("wordpress")

        self.assertEqual(plugin0, {"key": "plugins/plugin0", "version": "2.0"})
        self.assertEqual(plugin1, {"key": "plugins/plugin1", "version": "1.5"})
        self.assertEqual(theme0, {"key": "themes/theme0", "version": "4.5"})
        self.assertEqual(theme1, {"key": "themes/theme1", "version": "3.2.1"})
        self.assertEqual(wordpress, {"version": "4.2.2"})

    def test_format_return_data_formatted_to_pretty_output_if_output_format_is_pretty(self):
        self.output_manager.output_format = "pretty"
        self.output_manager._to_pretty_output = MagicMock(return_value="Pretty Output")

        pretty_output = self.output_manager._format("data")

        self.output_manager._to_pretty_output.assert_called_once_with("data")
        self.assertEqual(pretty_output, "Pretty Output")

    def test_to_pretty_output_put_component_meta_and_version_on_a_single_line(self):
        with patch("vane.outputmanager.termcolor.colored", fake_colored):
            wordpress_meta = Meta(key="wordpress", name="Wordpress", url="https://wordpress.org/")
            self.output_manager.set_wordpress_version("4.7.5", wordpress_meta)

            pretty_output = self.output_manager._to_pretty_output(self.output_manager.data)

            self.assertEqual(pretty_output, "Wordpress version 4.7.5\turl: https://wordpress.org/\n\n")

    def test_to_pretty_output_regroup_related_components(self):
        with patch("vane.outputmanager.termcolor.colored", fake_colored):
            plugin0_meta = Meta(key="plugins/plugin0", name="Plugin 0", url="https://www.plugin0.com/")
            plugin1_meta = Meta(key="plugins/plugin1", name="Plugin 1", url="https://www.plugin1.com/")
            self.output_manager.add_plugin("plugins/plugin0", "1.2.3", plugin0_meta)
            self.output_manager.add_plugin("plugins/plugin1", "4.5.6", plugin1_meta)
            theme0_meta = Meta(key="themes/theme0", name="Theme 0", url="https://www.theme0.com/")
            theme1_meta = Meta(key="themes/theme1", name="Theme 1", url="https://www.theme1.com/")
            self.output_manager.add_theme("themes/theme0", "3.2.1", theme0_meta)
            self.output_manager.add_theme("themes/theme1", "1.2.0", theme1_meta)

            output = self.output_manager._to_pretty_output(self.output_manager.data)

            self.assertIn("Plugins:\nPlugin 0 version 1.2.3\turl: https://www.plugin0.com/\n\n"
                          "Plugin 1 version 4.5.6\turl: https://www.plugin1.com/\n\n", output)
            self.assertIn("Themes:\nTheme 0 version 3.2.1\turl: https://www.theme0.com/\n\n"
                          "Theme 1 version 1.2.0\turl: https://www.theme1.com/\n\n", output)

    def test_to_pretty_output_set_components_group_name_in_blue_bold(self):
        plugin_meta = Meta(key="plugins/plugin", name="Plugin", url="https://www.plugin.com/")
        self.output_manager.add_plugin("plugins/plugin", "1.2.3", plugin_meta)
        theme_meta = Meta(key="themes/theme", name="Theme", url="https://www.theme.com/")
        self.output_manager.add_theme("themes/theme", "1.2.0", theme_meta)

        output = self.output_manager._to_pretty_output(self.output_manager.data)

        cyan_bold_char = "\x1B[{0}m\x1B[{1}m".format(termcolor.ATTRIBUTES["bold"], termcolor.COLORS["blue"])
        self.assertIn("%sPlugins:" % cyan_bold_char, output)
        self.assertIn("%sThemes:" % cyan_bold_char, output)

    def test_to_pretty_output_format_vulnerabilities_of_component(self):
        with patch("vane.outputmanager.termcolor.colored", fake_colored):
            plugin0_meta = Meta(key="plugins/plugin0", name="Plugin 0", url="https://www.plugin0.com/")
            plugin1_meta = Meta(key="plugins/plugin1", name="Plugin 1", url="https://www.plugin1.com/")
            self.output_manager.add_plugin("plugins/plugin0", "1.2.3", plugin0_meta)
            self.output_manager.add_plugin("plugins/plugin1", "4.5.6", plugin1_meta)
            self.output_manager.add_vulnerability("plugins/plugin0", {"id": "12345", "title": "vuln"})
            self.output_manager.add_vulnerability("plugins/plugin1", {"id": "23456", "title": "vuln"})

            output = self.output_manager._to_pretty_output(self.output_manager.data)

            self.assertEqual("Plugins:\nPlugin 0 version 1.2.3\turl: https://www.plugin0.com/\nVulnerabilities:\nvuln\n\n"
                             "Plugin 1 version 4.5.6\turl: https://www.plugin1.com/\nVulnerabilities:\nvuln\n\n", output)

    def test_to_pretty_output_format_general_log(self):
        with patch("vane.outputmanager.termcolor.colored", fake_colored):
            self.output_manager.log_message("message 0")
            self.output_manager.log_message("message 1")
            self.output_manager.log_message("message 2")

            output = self.output_manager._to_pretty_output(self.output_manager.data)

            self.assertEqual(output, "General Log:\nmessage 0\nmessage 1\nmessage 2\n")

    def test_to_pretty_output_format_output_with_defined_order(self):
        with patch("vane.outputmanager.termcolor.colored", fake_colored):
            self.output_manager.log_message("message...")
            self.output_manager.add_plugin("plugins/plugin", "1.2.3", Meta(key="plugins/plugin", name="Plugin", url="url"))
            self.output_manager.add_theme("themes/theme", "3.2.1", Meta(key="themes/theme", name="Theme", url="url"))
            self.output_manager.set_wordpress_version("4.3.1", Meta(key="wordpress", name="Wordpress", url="url"))

            output = self.output_manager._to_pretty_output(self.output_manager.data)

            expected_output = "{0}Plugins:\n{1}Themes:\n{2}General Log:\nmessage...\n"\
                .format(self.output_manager.print_component(self.output_manager.data["wordpress"]),
                        self.output_manager.print_component(self.output_manager.data["plugins"][0]),
                        self.output_manager.print_component(self.output_manager.data["themes"][0]))

            self.assertEqual(output, expected_output)

    def test_format_vulnerability_to_pretty_output(self):
        with patch("vane.outputmanager.termcolor.colored", fake_colored):
            vuln0 = {"id": "6556", "title": "Title of the vulnerability", "reported_type": "type",
                     "created_at": "2014-08-01T10:58:51+00:00", "updated_at": "2014-11-04T14:35:18+00:00",
                     "affected_versions": [{"introduced_in": "3.8.9.5"}], "references": [{"type": "osvdb", "id": "102484"},
                                                                                         {"type": "wpvulndb", "id": "6556"}]
                     }
            vuln1 = {"id": "CVE-2017-8295", "title": "Title of the vulnerability", "cvss": 4.3,
                     "description": "Description of the vulnerability", "reported_type": "CWE-640",
                     "created_at": "2017-05-03T00:00:00+00:00", "updated_at": "2017-05-18T16:18:00+00:00",
                     "affected_versions": [{"introduced_in": "4.7.0", "fixed_in": "4.7.5"}],
                     "references": [{"type": "cve", "id": "2017-8295",
                                     "url": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-8295"},
                                    {"type": "bugtraqid", "id": "98295"}]
                     }

            pretty_vuln0 = self.output_manager._format_vulnerability_to_pretty_output(vuln0)
            pretty_vuln1 = self.output_manager._format_vulnerability_to_pretty_output(vuln1)

            self.assertEqual(pretty_vuln0, "Title of the vulnerability\nIntroduced in: 3.8.9.5\nReferences:\n\tosvdb:"
                                           " 102484\n\twpvulndb: 6556\n")
            self.assertEqual(pretty_vuln1, "Title of the vulnerability\nDescription of the vulnerability\n"
                                           "Introduced in: 4.7.0\nFixed in: 4.7.5\nReferences:\n\tcve: 2017-8295"
                                           " url: https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2017-8295\n"
                                           "\tbugtraqid: 98295\n")

    def test_format_vulnerability_to_pretty_output_set_vuln_title_in_bold_yellow(self):
        vuln = {"id": "6556", "title": "Title of the vulnerability"}

        pretty_vuln = self.output_manager._format_vulnerability_to_pretty_output(vuln)

        esc_char = "\x1B[%d"
        self.assertIn(esc_char % termcolor.COLORS["yellow"], pretty_vuln)
        self.assertIn(esc_char % termcolor.ATTRIBUTES["bold"], pretty_vuln)

    def test_print_vulnerability_reference_indent_references(self):
        ref = {"type": "cve", "id": "2017-8295"}

        pretty_ref = self.output_manager.print_vulnerability_reference(ref, indent_level=1)

        self.assertEqual(pretty_ref, "\tcve: 2017-8295\n")

    def test_print_component_add_emptyline_at_end(self):
        component = {'name': 'Name', 'version': '1.0', 'url': 'http://url.something'}

        output = self.output_manager.print_component(component)

        self.assertTrue(output.endswith("\n\n"))

    def test_print_component_set_component_first_line_in_bold_green(self):
        component = {'name': 'Name', 'version': '1.0', 'url': 'http://url.something'}

        output = self.output_manager.print_component(component)

        esc_char = "\x1B[%d"
        self.assertIn(esc_char % termcolor.COLORS["green"], output)
        self.assertIn(esc_char % termcolor.ATTRIBUTES["bold"], output)

    def test_print_component_set_vulnerabilities_first_line_in_bold_red(self):
        self.output_manager.add_plugin("plugins/plugin", "1.0", Meta(key="plugins/plugin", name="Plugin", url="url"))
        self.output_manager.add_vulnerability("plugins/plugin", {"id": "1234", "title": "Title of the vuln."})

        output = self.output_manager.print_component(self.output_manager.data["plugins"][0])

        esc_char = "\x1B[%d"
        self.assertIn(esc_char % termcolor.COLORS["red"], output)
        self.assertIn(esc_char % termcolor.ATTRIBUTES["bold"], output)


def fake_colored(text, *args, **kwargs):
    return text
