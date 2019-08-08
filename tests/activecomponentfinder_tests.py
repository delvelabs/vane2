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

from os.path import dirname, join
from unittest import TestCase
from unittest.mock import MagicMock, call

from hammertime.core import HammerTime
from hammertime.rules.deadhostdetection import OfflineHostException
from openwebvulndb.common.models import File, FileList, FileSignature, FileListGroup

from fixtures import async_test
from vane.activecomponentfinder import ActiveComponentFinder
from vane.filefetcher import FetchedFile


class TestActiveComponentFinder(TestCase):

    def setUp(self):
        self.path_prefix = "wp-content/plugins/"
        self.plugin0_readme_file = File(path=self.path_prefix + "plugin0/readme.txt",
                                        signatures=[FileSignature(hash="1")])
        self.plugin0_style_file = File(path=self.path_prefix + "plugin0/style.css", signatures=[FileSignature(hash="2")])
        self.plugin0_file_list = FileList(key="plugins/plugin0", producer="unittest", files=[self.plugin0_readme_file,
                                                                                             self.plugin0_style_file])
        self.plugin1_readme_file = File(path=self.path_prefix + "plugin1/readme.txt",
                                        signatures=[FileSignature(hash="3")])
        self.plugin1_style_file = File(path=self.path_prefix + "plugin1/style.css", signatures=[FileSignature(hash="4")])
        self.plugin1_file_list = FileList(key="plugins/plugin1", producer="unittest", files=[self.plugin1_readme_file,
                                                                                             self.plugin1_style_file])
        self.plugin_list = FileListGroup(key="plugins", producer="unittest",
                                         file_lists=[self.plugin0_file_list, self.plugin1_file_list])
        self.target_url = "http://www.example.com"
        self.component_finder = ActiveComponentFinder(MagicMock(), self.target_url)
        self.component_finder.file_fetcher = MagicMock()

    def test_load_components_identification_file(self):
        file_path = join(dirname(__file__), "samples")

        self.component_finder.load_components_identification_file(file_path, "plugins", False, False)

        self.assertEqual(self.component_finder.components_file_list_group, self.plugin_list)

    def test_load_popular_components_identification_file(self):
        popular_plugin_list = FileListGroup(key="popular_plugins", producer="unittest", file_lists=[
            FileList(key="plugins/my-plugin", producer="unittest",
                     files=[File(path=self.path_prefix + "my-plugin/readme.txt")])
        ])
        file_path = join(dirname(__file__), "samples")

        self.component_finder.load_components_identification_file(file_path, "plugins", True, False)

        self.assertEqual(self.component_finder.components_file_list_group, popular_plugin_list)

    def test_load_vulnerable_components_identification_file(self):
        vulnerable_plugin_list = FileListGroup(key="vulnerable_plugins", producer="unittest", file_lists=[
            FileList(key="plugins/hack-me-plugin", producer="unittest",
                     files=[File(path=self.path_prefix + "hack-me-plugin/readme.html")])
        ])
        file_path = join(dirname(__file__), "samples")

        self.component_finder.load_components_identification_file(file_path, "plugins", False, True)

        self.assertEqual(self.component_finder.components_file_list_group, vulnerable_plugin_list)

    def test_load_vulnerable_and_popular_components_identification_files(self):
        popular_plugin_list = FileListGroup(key="plugins", producer="unittest", file_lists=[
            FileList(key="plugins/my-plugin", producer="unittest",
                     files=[File(path=self.path_prefix + "my-plugin/readme.txt")])
        ])
        vulnerable_plugin_list = FileListGroup(key="plugins", producer="unittest", file_lists=[
            FileList(key="plugins/hack-me-plugin", producer="unittest",
                     files=[File(path=self.path_prefix + "hack-me-plugin/readme.html")])
        ])
        file_path = join(dirname(__file__), "samples")

        self.component_finder.load_components_identification_file(file_path, "plugins", True, True)

        self.assertIn(popular_plugin_list.file_lists[0], self.component_finder.components_file_list_group.file_lists)
        self.assertIn(vulnerable_plugin_list.file_lists[0], self.component_finder.components_file_list_group.file_lists)

    def test_load_components_identification_file_with_different_component_base_key(self):
        path_prefix = "wp-content/themes/"
        theme0_readme_file = File(path=path_prefix + "theme0/readme.txt", signatures=[FileSignature(hash="1")])
        theme0_style_file = File(path=path_prefix + "theme0/style.css", signatures=[FileSignature(hash="2")])
        theme0_file_list = FileList(key="themes/theme0", producer="unittest", files=[theme0_readme_file,
                                                                                     theme0_style_file])
        theme1_readme_file = File(path=path_prefix + "theme1/readme.txt", signatures=[FileSignature(hash="3")])
        theme1_style_file = File(path=path_prefix + "theme1/style.css", signatures=[FileSignature(hash="4")])
        theme1_file_list = FileList(key="themes/theme1", producer="unittest", files=[theme1_readme_file,
                                                                                     theme1_style_file])
        theme_list = FileListGroup(key="themes", producer="unittest", file_lists=[theme0_file_list, theme1_file_list])
        file_path = join(dirname(__file__), "samples")

        self.component_finder.load_components_identification_file(file_path, "themes", False, False)

        self.assertEqual(self.component_finder.components_file_list_group, theme_list)

    @async_test()
    async def test_enumerate_found_fetch_version_definitions_files_for_component(self, loop):

        async def request_files():
            return self.plugin0_file_list.key, [FetchedFile(path=self.plugin0_readme_file.path, hash="fake-hash")]

        self.component_finder.loop = loop
        self.component_finder.file_fetcher.request_files.return_value = loop.create_task(request_files())
        self.component_finder.components_file_list_group = FileListGroup(key="plugins", producer="",
                                                                         file_lists=[self.plugin0_file_list])

        plugins = await self.return_async_iterator_as_list(self.component_finder.enumerate_found())

        self.component_finder.file_fetcher.request_files.assert_has_calls(
            [call(self.plugin0_file_list.key, self.plugin0_file_list)])
        self.assertIn(self.plugin0_file_list.key, [plugin['key'] for plugin in plugins])

    @async_test()
    async def test_enumerate_found_skip_component_with_no_files(self, loop):
        self.component_finder.loop = loop
        plugin0 = FileList(key="plugins/plugin0", producer="", files=[])
        self.component_finder.components_file_list_group = FileListGroup(key="plugins", producer="",
                                                                         file_lists=[plugin0])

        plugins = await self.return_async_iterator_as_list(self.component_finder.enumerate_found())

        self.component_finder.file_fetcher.request_files.assert_not_called()
        self.assertEqual(len(plugins), 0)

    @async_test()
    async def test_enumerate_found_return_list_of_dict_with_component_key_and_fetched_files(self, loop):

        async def fake_perform(entry, *args, **kwargs):
            entry.result.hash = "fake-hash"
            return entry

        hammertime = HammerTime(loop)
        hammertime.request_engine = MagicMock()
        hammertime.request_engine.perform = fake_perform
        component_finder = ActiveComponentFinder(hammertime, self.target_url)
        component_finder.components_file_list_group = self.plugin_list

        components = await self.return_async_iterator_as_list(component_finder.enumerate_found())

        for component_dict in components:
            self.assertTrue(component_dict['key'] == self.plugin0_file_list.key or
                            component_dict['key'] == self.plugin1_file_list.key)
            self.assertIn('files', component_dict)

    @async_test()
    async def test_enumerate_found_raise_if_host_is_offline(self, loop):

        async def fake_perform(*args, **kwargs):
            raise OfflineHostException()

        hammertime = HammerTime(loop)
        hammertime.request_engine = MagicMock()
        hammertime.request_engine.perform = fake_perform
        component_finder = ActiveComponentFinder(hammertime, self.target_url)
        component_finder.components_file_list_group = self.plugin_list

        with self.assertRaises(OfflineHostException):
            async for _ in component_finder.enumerate_found():
                pass

    def test_get_component_file_list(self):
        self.component_finder.components_file_list_group = self.plugin_list

        plugin0_file_list = self.component_finder.get_component_file_list(self.plugin0_file_list.key)
        plugin1_file_list = self.component_finder.get_component_file_list(self.plugin1_file_list.key)

        self.assertEqual(plugin0_file_list, self.plugin0_file_list)
        self.assertEqual(plugin1_file_list, self.plugin1_file_list)

    @staticmethod
    async def return_async_iterator_as_list(async_iterator):
        li = []
        async for element in async_iterator:
            li.append(element)
        return li
