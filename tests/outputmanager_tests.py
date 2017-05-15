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

from vane.outputmanager import OutputManager
from openwebvulndb.common.models import Meta


class TestOutputManager(TestCase):

    def setUp(self):
        self.fake_meta = Meta(key="meta", name="Name", url="example.com")

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

        output_manager.add_plugin("plugin1", "4.7.2", None)

        self.assertEqual(output_manager.data["plugins"], [{'key': "plugin0", 'version': "2.1"},
                                                          {'key': "plugin1", 'version': "4.7.2"}])

    def test_output_manager_add_themes_append_theme_to_theme_list(self):
        output_manager = OutputManager()
        output_manager.data["themes"] = [{'key': "theme0", 'version': "1.2.3"}]

        output_manager.add_theme("theme1", "6.1", None)

        self.assertEqual(output_manager.data["themes"], [{'key': "theme0", 'version': "1.2.3"},
                                                         {'key': "theme1", 'version': "6.1"}])

    def test_add_component_merge_meta_name_and_url_with_component(self):
        output_manager = OutputManager()

        output_manager._add_component("plugins", "plugins/my-plugin", "1.2", self.fake_meta)
        output_manager._add_component("themes", "themes/my-theme", "2.0", self.fake_meta)

        self.assertEqual(output_manager.data["plugins"], [{"key": "plugins/my-plugin", "version": "1.2",
                                                           "name": self.fake_meta.name, "url": self.fake_meta.url}])
        self.assertEqual(output_manager.data["themes"], [{"key": "themes/my-theme", "version": "2.0",
                                                          "name": self.fake_meta.name, "url": self.fake_meta.url}])

    def test_output_manager_add_vulnerability_add_vulnerability_to_vuln_list_of_key(self):
        output_manager = OutputManager()
        output_manager.add_plugin("plugins/my-plugin", "1.0", None)
        output_manager.add_theme("themes/my-theme", "2.0", None)

        output_manager.add_vulnerability("plugins/my-plugin", "my-plugin-vulnerability")
        output_manager.add_vulnerability("themes/my-theme", "my-theme-vuln")

        self.assertEqual(output_manager.data["plugins"][0]["vulnerabilities"][0], "my-plugin-vulnerability")
        self.assertEqual(output_manager.data["themes"][0]["vulnerabilities"][0], "my-theme-vuln")

    def test_output_manager_add_vulnerability_append_vulnerability_to_vulnerabilities_list_of_key(self):
        output_manager = OutputManager()
        output_manager.add_plugin("plugins/my-plugin", "1.0", None)
        output_manager.add_vulnerability("plugins/my-plugin", "vulnerability0")

        output_manager.add_vulnerability("plugins/my-plugin", "vulnerability1")

        self.assertEqual(output_manager.data["plugins"][0]["vulnerabilities"], ["vulnerability0", "vulnerability1"])

    def test_output_manager_get_component_dictionary_return_dictionary_of_component_with_key_in_data(self):
        output_manager = OutputManager()
        output_manager.add_plugin("plugins/plugin0", "2.0", None)
        output_manager.add_plugin("plugins/plugin1", "1.5", None)
        output_manager.add_theme("themes/theme0", "4.5", None)
        output_manager.add_theme("themes/theme1", "3.2.1", None)
        output_manager.set_wordpress_version("4.2.2", None)

        plugin0 = output_manager._get_component_dictionary("plugins/plugin0")
        plugin1 = output_manager._get_component_dictionary("plugins/plugin1")
        theme0 = output_manager._get_component_dictionary("themes/theme0")
        theme1 = output_manager._get_component_dictionary("themes/theme1")
        wordpress = output_manager._get_component_dictionary("wordpress")

        self.assertEqual(plugin0, {"key": "plugins/plugin0", "version": "2.0"})
        self.assertEqual(plugin1, {"key": "plugins/plugin1", "version": "1.5"})
        self.assertEqual(theme0, {"key": "themes/theme0", "version": "4.5"})
        self.assertEqual(theme1, {"key": "themes/theme1", "version": "3.2.1"})
        self.assertEqual(wordpress, {"version": "4.2.2"})