from unittest import TestCase
from unittest.mock import MagicMock, call
from vane.activethemesfinder import ActiveThemesFinder
from openwebvulndb.common.models import FileListGroup, FileList, File, FileSignature
from os.path import join, dirname
from aiohttp.test_utils import loop_context, make_mocked_coro
import asyncio
from vane.filefetcher import FetchedFile
from hammertime import HammerTime


class TestActiveThemesFinder(TestCase):

    def setUp(self):
        self.path_prefix = "wp-content/themes/"
        self.theme0_readme_file = File(path=self.path_prefix + "theme0/readme.txt", signatures=[FileSignature(hash="1")])
        self.theme0_style_file = File(path=self.path_prefix + "theme0/style.css", signatures=[FileSignature(hash="2")])
        self.theme0_file_list = FileList(key="themes/theme0", producer="unittest", files=[self.theme0_readme_file,
                                                                                          self.theme0_style_file])
        self.theme1_readme_file = File(path=self.path_prefix + "theme1/readme.txt", signatures=[FileSignature(hash="3")])
        self.theme1_style_file = File(path=self.path_prefix + "theme1/style.css", signatures=[FileSignature(hash="4")])
        self.theme1_file_list = FileList(key="themes/theme1", producer="unittest", files=[self.theme1_readme_file,
                                                                                          self.theme1_style_file])
        self.theme_list = FileListGroup(key="themes", producer="unittest",
                                        file_lists=[self.theme0_file_list, self.theme1_file_list])
        self.target_url = "http://www.example.com"
        self.themes_finder = ActiveThemesFinder(MagicMock(), self.target_url)
        self.themes_finder.file_fetcher = MagicMock()

    def test_load_themes_files_signatures(self):
        popular_theme_list = FileListGroup(key="popular_themes", producer="unittest", file_lists=[
            FileList(key="themes/my-theme", producer="unittest",
                     files=[File(path=self.path_prefix + "my-theme/readme.txt")])
        ])
        vulnerable_theme_list = FileListGroup(key="vulnerable_themes", producer="unittest", file_lists=[
            FileList(key="themes/vuln-theme", producer="unittest",
                     files=[File(path=self.path_prefix + "vuln-theme/readme.html")])
        ])
        file_path = join(dirname(__file__), "samples")

        self.themes_finder.load_themes_files_signatures(file_path)

        self.assertEqual(self.themes_finder.themes_file_list, self.theme_list)
        self.assertEqual(self.themes_finder.popular_themes_file_list, popular_theme_list)
        self.assertEqual(self.themes_finder.vulnerable_themes_file_list, vulnerable_theme_list)

    def test_enumerate_themes_fetch_all_version_definitions_files_for_theme(self):
        with loop_context() as loop:
            @asyncio.coroutine
            def request_files():
                return self.theme0_file_list.key, [FetchedFile(path=self.theme0_readme_file.path, hash="fake-hash")]

            self.themes_finder.loop = loop
            self.themes_finder.file_fetcher.request_files.return_value = loop.create_task(request_files())
            themes_file_list = FileListGroup(key="themes", producer="", file_lists=[self.theme0_file_list])

            themes, errors = loop.run_until_complete(self.themes_finder.enumerate_themes(themes_file_list))

            self.themes_finder.file_fetcher.request_files.assert_has_calls([call(self.theme0_file_list.key,
                                                                                 self.theme0_file_list)])
            self.assertIn(self.theme0_file_list.key, [theme['key'] for theme in themes])

    def test_enumerate_themes_skip_themes_with_no_files(self):
        with loop_context() as loop:
            self.themes_finder.loop = loop
            themes_file_list = FileListGroup(key="themes", producer="", file_lists=[])

            themes, errors = loop.run_until_complete(self.themes_finder.enumerate_themes(themes_file_list))

            self.themes_finder.file_fetcher.request_files.assert_not_called()
            self.assertEqual(len(themes), 0)

    def test_enumerate_themes_return_list_of_dict_with_theme_key_and_fetched_files(self):
        @asyncio.coroutine
        def fake_perform(entry, *args, **kwargs):
            entry.result.hash = "fake-hash"
            return entry

        with loop_context() as loop:
            asyncio.set_event_loop(loop)
            hammertime = HammerTime()
            hammertime.request_engine = MagicMock()
            hammertime.request_engine.perform = fake_perform
            themes_finder = ActiveThemesFinder(hammertime, self.target_url)

            themes, errors = loop.run_until_complete(themes_finder.enumerate_themes(self.theme_list))

            for theme in themes:
                self.assertTrue(theme['key'] == self.theme0_file_list.key or theme['key'] == self.theme1_file_list.key)
                self.assertIn('files', theme)

    def test_enumerate_popular_themes_call_enumerate_themes_with_popular_themes_files(self):
        self.themes_finder.popular_themes_file_list = "list"
        self.themes_finder.enumerate_themes = make_mocked_coro(("themes", "errors"))

        with loop_context() as loop:
            loop.run_until_complete(self.themes_finder.enumerate_popular_themes())

            self.themes_finder.enumerate_themes.assert_called_once_with(self.themes_finder.popular_themes_file_list)

    def test_enumerate_vulnerable_plugins_call_enumerate_plugins_with_vulnerable_plugins_files(self):
        self.themes_finder.vulnerable_themes_file_list = "list"
        self.themes_finder.enumerate_themes = make_mocked_coro(("themes", "errors"))

        with loop_context() as loop:
            loop.run_until_complete(self.themes_finder.enumerate_vulnerable_themes())

            self.themes_finder.enumerate_themes.assert_called_once_with(self.themes_finder.vulnerable_themes_file_list)

    def test_enumerate_all_plugins_call_enumerate_plugins_with_all_plugins_files(self):
        self.themes_finder.themes_file_list = "list"
        self.themes_finder.enumerate_themes = make_mocked_coro(("themes", "errors"))

        with loop_context() as loop:
            loop.run_until_complete(self.themes_finder.enumerate_all_themes())

            self.themes_finder.enumerate_themes.assert_called_once_with(self.themes_finder.themes_file_list)
