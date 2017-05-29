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
from unittest.mock import patch, MagicMock, ANY
from vane.database import Database
from aiohttp.test_utils import make_mocked_coro, loop_context
from fixtures import async_test, AsyncContextManagerMock
from datetime import datetime
from freezegun import freeze_time
from aiohttp import ClientError


class TestDatabase(TestCase):

    def setUp(self):
        self.database = Database()
        self.database.get_days_since_last_update = MagicMock(return_value=0)
        self.database.configure_data_repository("Owner", "database")
        self.filename = "vane_data.tar.gz"
        self.database.aiohttp_session = MagicMock()
        response = MagicMock()
        response.status = 200
        response.read = make_mocked_coro(return_value="data")
        self.database.aiohttp_session.get.return_value = AsyncContextManagerMock(aenter_return=response)
        self.database.save_data_to_file = MagicMock()
        self.database.extract_downloaded_files = MagicMock()
        self.database.cleanup_archive_file = MagicMock()
        self.glob_mock = MagicMock()
        self.glob_patch = patch("vane.database.glob.glob", self.glob_mock)
        self.glob_patch.start()

    def tearDown(self):
        self.glob_patch.stop()

    def test_load_database_download_database_if_update_required(self):
        self.database.download_data_latest_release = make_mocked_coro()
        self.database.is_update_required = MagicMock(return_value=True)
        with loop_context() as loop:
            self.database.loop = loop

            self.database.load_data("path")

            self.database.download_data_latest_release.assert_called_once_with("path")

    def test_load_database_set_database_path(self):
        self.database.download_data_latest_release = make_mocked_coro()
        self.database.is_update_required = MagicMock(return_value=False)
        self.database.current_version = "1.2"
        with loop_context() as loop:
            self.database.loop = loop

            self.database.load_data("/path/to/database")

            self.assertEqual(self.database.database_path, "/path/to/database/vane2_data_1.2")

    def test_load_database_fallback_to_older_version_for_database_path_if_download_failed(self):
        self.database.download_data_latest_release = make_mocked_coro(raise_exception=ClientError())
        self.database.is_update_required = MagicMock(return_value=True)
        self.database.current_version = "1.2"
        with loop_context() as loop:
            self.database.loop = loop

            with self.assertRaises(ClientError):
                self.database.load_data("/path/to/database")

            self.assertEqual(self.database.database_path, "/path/to/database/vane2_data_1.2")

    def test_load_database_fallback_to_older_version_for_database_path_if_is_update_required_failed(self):
        self.database.is_update_required = MagicMock(side_effect=ClientError())
        self.database.current_version = "1.2"
        with loop_context() as loop:
            self.database.loop = loop

            with self.assertRaises(ClientError):
                self.database.load_data("/path/to/database")

            self.assertEqual(self.database.database_path, "/path/to/database/vane2_data_1.2")

    def test_is_update_required_return_true_if_data_folder_not_found(self):
        self.database.get_current_version = MagicMock(return_value=None)
        with loop_context() as loop:
            self.database.loop = loop

            self.assertTrue(self.database.is_update_required("path"))

    def test_is_update_required_return_true_if_files_missing(self):
        self.database.get_current_version = MagicMock(return_value="1.0")
        self.database.get_latest_release = make_mocked_coro(
            return_value={'tag_name': '1.0', 'id': "12345", 'assets': []})
        self.database.missing_files = MagicMock(return_value=True)
        with loop_context() as loop:
            self.database.loop = loop

            self.assertTrue(self.database.is_update_required("path"))

    def test_is_update_required_return_false_if_no_files_missing(self):
        self.database.get_current_version = MagicMock(return_value="1.0")
        self.database.missing_files = MagicMock(return_value=False)
        with loop_context() as loop:
            self.database.loop = loop

            self.assertFalse(self.database.is_update_required("path"))

    def test_is_update_required_return_true_if_installed_version_is_not_latest_version(self):
        with loop_context() as loop:
            self.database.loop = loop
            self.database.get_current_database_version = MagicMock(return_value="1.0")
            self.database.get_latest_release = make_mocked_coro(return_value=
                                                                {'tag_name': '2.0', 'id': "12345", 'assets': []})

            self.assertTrue(self.database.is_update_required("path"))

    def test_is_update_required_return_false_if_installed_version_is_latest_version(self):
        with loop_context() as loop:
            self.database.loop = loop
            self.database.get_current_version = MagicMock(return_value="1.0")
            self.database.get_latest_release = make_mocked_coro(return_value=
                                                                {'tag_name': '1.0', 'id': "12345", 'assets': []})

            self.assertFalse(self.database.is_update_required("path"))

    def test_is_update_required_check_if_new_version_available_if_last_update_older_than_auto_update_frequency(self):
        self.database.get_days_since_last_update = MagicMock(return_value=8)
        self.database.get_current_version = MagicMock(return_value="1.0")
        self.database.missing_files = MagicMock(return_value=False)
        self.database.get_latest_release = make_mocked_coro(return_value=
                                                            {'tag_name': '1.0', 'id': "12345", 'assets': []})
        with loop_context() as loop:
            self.database.loop = loop

            self.database.is_update_required("path")

            self.database.get_latest_release.assert_called_once_with()

    def test_is_update_required_dont_check_for_new_version_if_last_update_newer_than_auto_update_frequency(self):
        self.database.get_days_since_last_update = MagicMock(return_value=6)
        self.database.get_current_version = MagicMock(return_value="1.0")
        self.database.missing_files = MagicMock(return_value=False)
        self.database.get_latest_release = make_mocked_coro(return_value=
                                                            {'tag_name': '1.0', 'id': "12345", 'assets': []})
        with loop_context() as loop:
            self.database.loop = loop

            self.database.is_update_required("path")

            self.database.get_latest_release.assert_not_called()

    def test_is_update_required_dont_check_for_new_updates_if_no_update_is_true(self):
        self.database.auto_update_frequency = Database.ALWAYS_CHECK_FOR_UPDATE
        self.database.get_current_version = MagicMock(return_value="1.0")
        self.database.missing_files = MagicMock(return_value=False)
        with loop_context() as loop:
            self.database.loop = loop

            self.assertFalse(self.database.is_update_required("/path/to/database", no_update=True))

    def test_missing_files_look_for_vane_files_in_database_folder(self):
        self.database.files_to_check = ['vane2_wordpress_meta.json', 'vane2_wordpress_versions.json']
        isfile = MagicMock()

        with patch("vane.database.path.isfile", isfile):
            self.database.missing_files("/path/to/database", "1.2")
            calls = isfile.call_args_list
            for call, file in zip(calls, self.database.files_to_check):
                args, kwargs = call
                self.assertIn("/path/to/database/vane2_data_1.2/%s" % file, args)

    def test_missing_files_return_false_if_no_files_missing(self):
        self.database.files_to_check = ['vane2_wordpress_meta.json', 'vane2_wordpress_versions.json']
        isfile = MagicMock(return_value=True)

        with patch("vane.database.path.isfile", isfile):
            self.assertFalse(self.database.missing_files("/path/to/database", "1.2"))

    def test_missing_files_return_true_if_files_missing(self):
        self.database.files_to_check = ['vane2_wordpress_meta.json', 'vane2_wordpress_versions.json']
        isfile = MagicMock(return_value=False)

        with patch("vane.database.path.isfile", isfile):
            self.assertTrue(self.database.missing_files("/path/to/database", "1.2"))

    @async_test()
    async def test_download_database_request_vane_data_of_latest_release(self):
        self.database.get_latest_release = make_mocked_coro(return_value={"assets": [
            {'name': "vane2_data.tar.gz", 'url': self.database.api_url + "/releases/assets/1"},
            {'name': "other_asset", 'url': self.database.api_url + "/releases//assets/2"}]})
        self.database.get_data_filename = MagicMock(return_value="vane2_data.tar.gz")

        await self.database.download_data_latest_release("path")

        self.database.aiohttp_session.get.assert_called_once_with(self.database.api_url + "/releases/assets/1",
                                                                  headers=ANY)

    @async_test()
    async def test_download_database_set_current_version_attribute_to_latest_version(self):
        self.database.get_latest_release = make_mocked_coro(
            return_value={"tag_name": "1.5", "assets": [{'name': "vane2_data.tar.gz",
                                                         'url': self.database.api_url + "/releases/assets/1"}]})
        self.database.get_data_filename = MagicMock(return_value="vane2_data.tar.gz")

        await self.database.download_data_latest_release("path")

        self.assertEqual(self.database.current_version, "1.5")

    @async_test()
    async def test_download_database_set_accept_header_of_request(self):
        self.database.get_latest_release = make_mocked_coro(return_value={"assets": [
            {'name': "vane2_data.tar.gz", 'url': self.database.api_url + "/releases/assets/1"}]})
        self.database.get_data_filename = MagicMock(return_value="vane2_data.tar.gz")

        await self.database.download_data_latest_release("path")

        self.database.aiohttp_session.get.assert_called_once_with(ANY, headers={'accept': "application/octet-stream"})

    @async_test()
    async def test_download_database_cleanup_archive_file_after_extraction(self):
        self.database.get_latest_release = make_mocked_coro(return_value={"assets": [
            {'name': "vane2_data.tar.gz", 'url': self.database.api_url + "/releases/assets/1"}]})
        self.database.get_data_filename = MagicMock(return_value="vane2_data.tar.gz")

        await self.database.download_data_latest_release("path")

        self.database.cleanup_archive_file.assert_called_once_with("path/vane2_data.tar.gz")

    @async_test()
    async def test_get_latest_release_make_latest_release_request_to_github_api(self):
        await self.database.get_latest_release()

        self.database.aiohttp_session.get.assert_called_once_with(self.database.api_url + "/releases/latest")

    @async_test()
    async def test_get_latest_release_return_release(self):
        response = MagicMock()
        response.status = 200
        response.json = make_mocked_coro(return_value={'tag_name': '1.0', 'id': "12345", 'assets': []})
        self.database.aiohttp_session.get.return_value.aenter_return = response

        release = await self.database.get_latest_release()

        self.assertEqual(release, await response.json())

    def test_get_data_filename_return_basename_and_latest_release_version(self):
        latest_release = {'tag_name': "1.0"}

        filename = self.database.get_data_filename(latest_release)

        self.assertEqual(filename, "vane2_data_1.0.tar.gz")

    def test_get_current_version_search_in_database_path(self):
        self.database.get_current_version("path/to/vane2/database")

        self.glob_mock.assert_called_once_with("path/to/vane2/database/vane2_data_*")

    def test_get_current_version_latest_version_if_multiple_versions_are_found(self):
        self.glob_mock.return_value = ["vane2_data_1.0", "vane2_data_1.1"]

        version = self.database.get_current_version("path")

        self.assertEqual(version, "1.1")

    def test_get_current_version_return_none_if_no_database_found(self):
        self.glob_mock.return_value = []

        version = self.database.get_current_version("path")

        self.assertIsNone(version)

    def test_get_current_version_return_version_if_database_found(self):
        self.glob_mock.return_value = ["vane2_data_1.2"]

        version = self.database.get_current_version("path")

        self.assertEqual(version, "1.2")

    def test_get_current_version_set_database_version_attribute(self):
        self.glob_mock.return_value = ["vane2_data_1.2"]

        version = self.database.get_current_version("path")

        self.assertEqual(self.database.current_version, version)

    def test_get_current_version_calls_get_latest_installed_version_with_database_directories_relative_names(self):
        directory_list = ["vane2_data_1.2", "vane2_data_1.3", "vane2_data_1.5"]
        self.glob_mock.return_value = list("/absolute_path/" + directory for directory in directory_list)
        self.database.get_latest_installed_version = MagicMock()

        self.database.get_current_version("/absolute_path")

        self.database.get_latest_installed_version.assert_called_once_with(directory_list)

    def test_get_current_version_dont_pass_targz_database_files_to_get_latest_installed_version(self):
        directory_list = ["vane2_data_1.2", "vane2_data_1.2.tar.gz", "vane2_data_1.3.tar.gz"]
        self.glob_mock.return_value = directory_list
        self.database.get_latest_installed_version = MagicMock()

        self.database.get_current_version("path")

        self.database.get_latest_installed_version.assert_called_once_with(["vane2_data_1.2"])

    def test_get_latest_installed_version_return_latest_version_from_directory_name(self):
        database_directory = ["vane2_data_1.1", "vane2_data_1.2", "vane2_data_2.1"]

        latest_version = self.database.get_latest_installed_version(database_directory)

        self.assertEqual("2.1", latest_version)

    @freeze_time("2017-05-29")
    def test_get_days_since_last_update_return_time_in_days_between_now_and_database_folder_modification_time(self):
        database = Database()
        stat_result = MagicMock()
        stat_result.st_mtime = datetime(2017, 5, 24).timestamp()
        os_stat = MagicMock(return_value=stat_result)

        with patch('vane.database.stat', os_stat):
            days_since_last_update = database.get_days_since_last_update("path")

            self.assertEqual(days_since_last_update, 5)

    def test_cleanup_archive_file_remove_downloaded_archive_file(self):
        database = Database()
        fake_remove = MagicMock()
        with patch("vane.database.remove", fake_remove):

            database.cleanup_archive_file("filename.tar.gz")

            fake_remove.assert_called_once_with("filename.tar.gz")
