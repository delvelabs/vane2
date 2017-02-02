from unittest import TestCase
from unittest.mock import MagicMock, call
from openwebvulndb.common.models import File, FileList, FileSignature, FileListGroup
from vane.activepluginsfinder import ActivePluginsFinder
from aiohttp.test_utils import loop_context, make_mocked_coro
from os.path import dirname, join


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
        self.plugin_finder = ActivePluginsFinder(MagicMock())
        self.plugin_finder.version_identification = MagicMock()

    def test_load_plugins_files_signatures(self):
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

    def test_enumerate_plugins_fetch_all_version_definitions_files_for_each_plugin(self):
        self.plugin_finder.version_identification.fetch_files = make_mocked_coro(["fetched files"])
        self.plugin_finder.plugins_file_list = self.plugins_list
        target = "http://www.example.com"

        with loop_context() as loop:
            plugins = loop.run_until_complete(self.plugin_finder._enumerate_plugins(target, self.plugins_list))

            self.plugin_finder.version_identification.set_files_to_fetch.assert_has_calls([call(self.plugin0_file_list),
                                                                                      call(self.plugin1_file_list)])
            self.plugin_finder.version_identification.fetch_files.assert_has_calls([call(target), call(target)])
            self.assertIn(self.plugin0_file_list.key, plugins)
            self.assertIn(self.plugin1_file_list.key, plugins)

    def test_enumerate_plugins_skip_plugins_with_no_files(self):
        plugin2 = FileList(key="plugins/plugin2", producer="unittest")
        plugins_file_list = FileListGroup(key="plugins", producer="unittest", file_lists=[plugin2])
        self.plugin_finder.version_identification.fetch_files = make_mocked_coro(["fetched files"])
        target = "http://www.example.com"

        with loop_context() as loop:
            loop.run_until_complete(self.plugin_finder._enumerate_plugins(target, plugins_file_list))

            self.plugin_finder.version_identification.set_files_to_fetch.assert_not_called()

    def test_enumerate_popular_plugins_call_enumerate_plugins_with_popular_plugins_files(self):
        self.plugin_finder.popular_plugins_file_list = "list"
        self.plugin_finder._enumerate_plugins = make_mocked_coro()
        target = "target"

        with loop_context() as loop:
            loop.run_until_complete(self.plugin_finder.enumerate_popular_plugins(target))

            self.plugin_finder._enumerate_plugins.assert_called_once_with(target,
                                                                          self.plugin_finder.popular_plugins_file_list)

    def test_enumerate_vulnerable_plugins_call_enumerate_plugins_with_vulnerable_plugins_files(self):
        self.plugin_finder.vulnerable_plugins_file_list = "list"
        self.plugin_finder._enumerate_plugins = make_mocked_coro()
        target = "target"

        with loop_context() as loop:
            loop.run_until_complete(self.plugin_finder.enumerate_vulnerable_plugins(target))

            self.plugin_finder._enumerate_plugins.assert_called_once_with(target,
                                                                          self.plugin_finder.vulnerable_plugins_file_list)

    def test_enumerate_all_plugins_call_enumerate_plugins_with_all_plugins_files(self):
        self.plugin_finder.plugins_file_list = "list"
        self.plugin_finder._enumerate_plugins = make_mocked_coro()
        target = "target"

        with loop_context() as loop:
            loop.run_until_complete(self.plugin_finder.enumerate_all_plugins(target))

            self.plugin_finder._enumerate_plugins.assert_called_once_with(target,
                                                                          self.plugin_finder.plugins_file_list)
