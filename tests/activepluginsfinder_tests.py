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

    def test_load_plugins_files_signatures(self):
        self.skipTest("")
        popular_plugins_list = FileListGroup(key="popular_plugins", producer="unittest", file_lists=[
            FileList(key="plugins/my-plugin", producer="unittest",
                     files=[File(path=self.path_prefix + "my-plugin/readme.txt")])
        ])
        vulnerable_plugins_list = FileListGroup(key="vulnerable_plugins", producer="unittest", file_lists=[
            FileList(key="plugins/hack-me-plugin", producer="unittest",
                     files=[File(path=self.path_prefix + "hack-me-plugin/readme.html")])
        ])
        file_path = join(dirname(__file__), "samples")

        self.plugin_finder.load_plugins_files_signatures(file_path)

        self.assertEqual(self.plugin_finder.plugins_file_list, self.plugins_list)
        self.assertEqual(self.plugin_finder.popular_plugins_file_list, popular_plugins_list)
        self.assertEqual(self.plugin_finder.vulnerable_plugins_file_list, vulnerable_plugins_list)

    def test_enumerate_plugins_fetch_all_version_definitions_files_for_plugin(self):
        fetched_file = MagicMock()
        fetched_file.hash = "hash"
        with loop_context() as loop:
            @asyncio.coroutine
            def request_files():
                return self.plugin0_file_list.key, [FetchedFile(path=self.plugin0_readme_file.path, hash="fake-hash")]

            self.plugin_finder.loop = loop
            self.plugin_finder.file_fetcher.request_files.return_value = loop.create_task(request_files())
            plugins_file_list = FileListGroup(key="plugins", producer="", file_lists=[self.plugin0_file_list])

            plugins = loop.run_until_complete(self.plugin_finder.enumerate_plugins(self.target_url, plugins_file_list))

            self.plugin_finder.file_fetcher.request_files.assert_has_calls(
                [call(self.plugin0_file_list.key, self.plugin0_file_list)])
            self.assertIn(self.plugin0_file_list.key, plugins)

    def test_enumerate_plugins_skip_plugins_with_no_files(self):
        with loop_context() as loop:
            self.plugin_finder.loop = loop
            plugins_file_list = FileListGroup(key="plugins", producer="", file_lists=[])

            plugins = loop.run_until_complete(self.plugin_finder.enumerate_plugins(self.target_url, plugins_file_list))

            self.plugin_finder.file_fetcher.request_files.assert_not_called()
            self.assertEqual(len(plugins), 0)

    def test_enumerate_popular_plugins_call_enumerate_plugins_with_popular_plugins_files(self):
        self.plugin_finder.popular_plugins_file_list = "list"
        self.plugin_finder.enumerate_plugins = make_mocked_coro()
        target = "target"

        with loop_context() as loop:
            loop.run_until_complete(self.plugin_finder.enumerate_popular_plugins(target))

            self.plugin_finder.enumerate_plugins.assert_called_once_with(target,
                                                                         self.plugin_finder.popular_plugins_file_list)

    def test_enumerate_vulnerable_plugins_call_enumerate_plugins_with_vulnerable_plugins_files(self):
        self.plugin_finder.vulnerable_plugins_file_list = "list"
        self.plugin_finder.enumerate_plugins = make_mocked_coro()
        target = "target"

        with loop_context() as loop:
            loop.run_until_complete(self.plugin_finder.enumerate_vulnerable_plugins(target))

            self.plugin_finder.enumerate_plugins.assert_called_once_with(target, self.plugin_finder.vulnerable_plugins_file_list)

    def test_enumerate_all_plugins_call_enumerate_plugins_with_all_plugins_files(self):
        self.plugin_finder.plugins_file_list = "list"
        self.plugin_finder.enumerate_plugins = make_mocked_coro()
        target = "target"

        with loop_context() as loop:
            loop.run_until_complete(self.plugin_finder.enumerate_all_plugins(target))

            self.plugin_finder.enumerate_plugins.assert_called_once_with(target,
                                                                          self.plugin_finder.plugins_file_list)

    def test_enumerate_plugins_return_list_with_plugins_key(self):
        @asyncio.coroutine
        def fake_perform(entry, *args, **kwargs):
            entry.result.hash = "fake-hash"
            return entry

        with loop_context() as loop:
            hammertime = HammerTime(loop)
            hammertime.request_engine = MagicMock()
            hammertime.request_engine.perform = fake_perform
            plugin_finder = ActivePluginsFinder(hammertime, self.target_url)

            plugins = loop.run_until_complete(plugin_finder.enumerate_plugins(self.target_url, self.plugins_list))

            for plugin_key in plugins:
                self.assertTrue(plugin_key == self.plugin0_file_list.key or plugin_key == self.plugin1_file_list.key)
