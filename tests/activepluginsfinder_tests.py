from unittest import TestCase
from unittest.mock import MagicMock, call
from openwebvulndb.common.models import File, FileList, FileSignature, FileListGroup
from vane.activepluginsfinder import ActivePluginsFinder
from aiohttp.test_utils import loop_context, make_mocked_coro
from os.path import dirname, join
from hammertime.core import HammerTime
import asyncio
from vane.filefetcher import FetchedFile


class TestActivePluginFinder(TestCase):

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
        self.plugins_list = FileListGroup(key="plugins", producer="unittest",
                                          file_lists=[self.plugin0_file_list, self.plugin1_file_list])
        self.target_url = "http://www.example.com"
        self.plugin_finder = ActivePluginsFinder(MagicMock(), self.target_url)
        self.plugin_finder.file_fetcher = MagicMock()

    def test_load_all_plugins_files_signatures(self):
        file_path = join(dirname(__file__), "samples")

        self.plugin_finder.load_plugins_files_signatures(file_path, False, False)

        self.assertEqual(self.plugin_finder.plugins_file_list_group, self.plugins_list)

    def test_load_popular_plugins_files_signatures(self):
        popular_plugins_list = FileListGroup(key="popular_plugins", producer="unittest", file_lists=[
            FileList(key="plugins/my-plugin", producer="unittest",
                     files=[File(path=self.path_prefix + "my-plugin/readme.txt")])
        ])
        file_path = join(dirname(__file__), "samples")

        self.plugin_finder.load_plugins_files_signatures(file_path, True, False)

        self.assertEqual(self.plugin_finder.plugins_file_list_group, popular_plugins_list)

    def test_load_vulnerable_plugins_files_signatures(self):
        vulnerable_plugins_list = FileListGroup(key="vulnerable_plugins", producer="unittest", file_lists=[
            FileList(key="plugins/hack-me-plugin", producer="unittest",
                     files=[File(path=self.path_prefix + "hack-me-plugin/readme.html")])
        ])
        file_path = join(dirname(__file__), "samples")

        self.plugin_finder.load_plugins_files_signatures(file_path, False, True)

        self.assertEqual(self.plugin_finder.plugins_file_list_group, vulnerable_plugins_list)

    def test_enumerate_plugins_fetch_version_definitions_files_for_plugin(self):
        with loop_context() as loop:
            @asyncio.coroutine
            def request_files():
                return self.plugin0_file_list.key, [FetchedFile(path=self.plugin0_readme_file.path, hash="fake-hash")]

            self.plugin_finder.loop = loop
            self.plugin_finder.file_fetcher.request_files.return_value = loop.create_task(request_files())
            self.plugin_finder.plugins_file_list_group = FileListGroup(key="plugins", producer="",
                                                                       file_lists=[self.plugin0_file_list])

            plugins, errors = loop.run_until_complete(self.plugin_finder.enumerate_plugins())

            self.plugin_finder.file_fetcher.request_files.assert_has_calls(
                [call(self.plugin0_file_list.key, self.plugin0_file_list)])
            self.assertIn(self.plugin0_file_list.key, [plugin['key'] for plugin in plugins])

    def test_enumerate_plugins_skip_plugins_with_no_files(self):
        with loop_context() as loop:
            self.plugin_finder.loop = loop
            plugin0 = FileList(key="plugins/plugin0", producer="", files=[])
            self.plugin_finder.plugins_file_list_group = FileListGroup(key="plugins", producer="", file_lists=[plugin0])

            plugins, errors = loop.run_until_complete(self.plugin_finder.enumerate_plugins())

            self.plugin_finder.file_fetcher.request_files.assert_not_called()
            self.assertEqual(len(plugins), 0)

    def test_enumerate_plugins_return_list_of_dict_with_plugin_key_and_fetched_files(self):
        @asyncio.coroutine
        def fake_perform(entry, *args, **kwargs):
            entry.result.hash = "fake-hash"
            return entry

        with loop_context() as loop:
            hammertime = HammerTime(loop)
            hammertime.request_engine = MagicMock()
            hammertime.request_engine.perform = fake_perform
            plugin_finder = ActivePluginsFinder(hammertime, self.target_url)
            plugin_finder.plugins_file_list_group = self.plugins_list

            plugins, errors = loop.run_until_complete(plugin_finder.enumerate_plugins())

            for plugin_dict in plugins:
                self.assertTrue(plugin_dict['key'] == self.plugin0_file_list.key or
                                plugin_dict['key'] == self.plugin1_file_list.key)
                self.assertIn('files', plugin_dict)
