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
from aiohttp.test_utils import make_mocked_coro
from fixtures import async_test, AsyncContextManagerMock
from datetime import datetime
from freezegun import freeze_time
from aiohttp import ClientError


class TestDatabase(TestCase):

    def setUp(self):
        self.database = Database(MagicMock())
        self.database.required_files = []
        self.database._get_days_since_last_update = MagicMock(return_value=0)
        self.database.aiohttp_session = MagicMock()
        self.response = MagicMock()
        self.response.status = 200
        self.response.read = make_mocked_coro(return_value="data")
        self.database.aiohttp_session.get.return_value = AsyncContextManagerMock(aenter_return=self.response)
        self.database.save_data_to_archive_file = MagicMock()
        self.database.extract_downloaded_files = MagicMock()
        self.database.cleanup_archive_file = MagicMock()
        self.database.get_data_archive_name = MagicMock(return_value="vane2_data.tar.gz")
        self.glob_mock = MagicMock()
        glob_patch = patch("vane.database.glob.glob", self.glob_mock)
        glob_patch.start()
        self.addCleanup(glob_patch.stop)

    @async_test()
    async def test_load_database_download_database_if_update_required(self):
        self.database.download_data_latest_release = make_mocked_coro()
        self.database.is_update_required = make_mocked_coro(return_value=True)

        await self.database.load_data("path")

        self.database.download_data_latest_release.assert_called_once_with("path")

    @async_test()
    async def test_load_database_dont_call_is_update_required_and_dont_download_update_if_no_update_is_true(self):
        self.database.current_version = "1.0"
        self.database._is_database_present = MagicMock(return_value=True)
        self.database.is_update_required = make_mocked_coro(return_value=True)
        self.database.download_data_latest_release = make_mocked_coro()

        await self.database.load_data("/path/to/database", no_update=True)

        self.database.download_data_latest_release.assert_not_called()
        self.database.is_update_required.assert_not_called()

    @async_test()
    async def test_load_database_set_database_directory_to_none_if_no_database_found_and_no_update_is_true(self):
        self.database.download_data_latest_release = make_mocked_coro()
        self.database._is_database_present = MagicMock(return_value=False)
        self.database.is_update_required = make_mocked_coro()

        await self.database.load_data("path", no_update=True)

        self.database.download_data_latest_release.assert_not_called()
        self.assertIsNone(self.database.database_directory)

    @async_test()
    async def test_load_database_set_database_directory(self):
        self.database.download_data_latest_release = make_mocked_coro()
        self.database.is_update_required = make_mocked_coro(return_value=False)
        self.database.current_version = "1.2"
        self.database._is_database_present = MagicMock(return_value=True)

        await self.database.load_data("/path/to/database")

        self.assertEqual(self.database.database_directory, "/path/to/database/vane2_data_1.2")

    @async_test()
    async def test_load_database_fallback_to_older_version_for_database_directory_if_download_failed(self):
        self.database.download_data_latest_release = make_mocked_coro(raise_exception=ClientError())
        self.database._is_database_present = MagicMock(return_value=True)
        self.database.is_update_required = make_mocked_coro(return_value=True)
        self.database.current_version = "1.2"

        with self.assertRaises(ClientError):
            await self.database.load_data("/path/to/database")

        self.assertEqual(self.database.database_directory, "/path/to/database/vane2_data_1.2")

    @async_test()
    async def test_load_database_fallback_to_older_version_for_database_directory_if_is_update_required_failed(self):
        self.database.is_update_required = make_mocked_coro(raise_exception=ClientError())
        self.database.current_version = "1.2"
        self.database._is_database_present = MagicMock(return_value=True)

        with self.assertRaises(ClientError):
            await self.database.load_data("/path/to/database")

        self.assertEqual(self.database.database_directory, "/path/to/database/vane2_data_1.2")

    @async_test()
    async def test_load_database_log_message_if_download_successful(self):
        self.database.is_update_required = make_mocked_coro(return_value=True)
        self.database.download_data_latest_release = make_mocked_coro()
        self.database.current_version = "1.2"
        self.database._is_database_present = MagicMock(return_value=True)

        await self.database.load_data("/path/to/database")

        self.database.output_manager.log_message.assert_called_once_with("Database update done")

    @async_test()
    async def test_is_update_required_return_true_if_installed_version_is_not_latest_version(self):
        self.database.auto_update_frequency = Database.ALWAYS_CHECK_FOR_UPDATE
        self.database.current_version = "1.0"
        self.database.get_latest_release = make_mocked_coro(return_value={'tag_name': '2.0'})

        self.assertTrue(await self.database.is_update_required("path"))

    @async_test()
    async def test_is_update_required_log_message_if_new_version_available(self):
        self.database.current_version = "1.0"
        self.database.auto_update_frequency = Database.ALWAYS_CHECK_FOR_UPDATE
        self.database.get_latest_release = make_mocked_coro(return_value={'tag_name': '2.0'})

        await self.database.is_update_required("path")

        self.database.output_manager.log_message.assert_called_once_with("New database version available: 2.0")

    @async_test()
    async def test_is_update_required_return_false_if_current_version_is_latest_version(self):
        self.database.current_version = "1.0"
        self.database.auto_update_frequency = Database.ALWAYS_CHECK_FOR_UPDATE
        self.database.get_latest_release = make_mocked_coro(return_value={'tag_name': '1.0'})

        self.assertFalse(await self.database.is_update_required("path"))

    @async_test()
    async def test_is_update_required_check_for_new_version_if_last_update_older_than_auto_update_frequency(self):
        self.database._get_days_since_last_update = MagicMock(return_value=self.database.auto_update_frequency + 1)
        self.database.current_version = "1.0"
        self.database.get_latest_release = make_mocked_coro(return_value={'tag_name': '2.0'})

        await self.database.is_update_required("path")

        self.database.get_latest_release.assert_called_once_with()

    @async_test()
    async def test_is_update_required_log_message_if_current_version_is_up_to_date(self):
        self.database.auto_update_frequency = Database.ALWAYS_CHECK_FOR_UPDATE
        self.database.current_version = "2.0"
        self.database.get_latest_release = make_mocked_coro(return_value={'tag_name': '2.0'})

        await self.database.is_update_required("path")

        self.database.output_manager.log_message.assert_called_once_with("Database version is latest version available")

    @async_test()
    async def test_is_update_required_dont_check_for_new_version_if_last_update_newer_than_auto_update_frequency(self):
        self.database._get_current_version = MagicMock(return_value="1.0")
        self.database._missing_files = MagicMock(return_value=False)
        self.database.get_latest_release = make_mocked_coro(return_value={'tag_name': '2.0'})
        self.database._get_days_since_last_update(self.database.auto_update_frequency - 1)

        await self.database.is_update_required("path")

        self.database.get_latest_release.assert_not_called()

    def test_is_database_present_set_current_version_to_none_and_return_false_if_no_database_found(self):
        self.database._get_current_version = MagicMock(return_value=None)

        database_present = self.database._is_database_present("/path/to/database")

        self.assertFalse(database_present)
        self.assertIsNone(self.database.current_version)

    def test_is_database_present_set_current_version_to_none_and_return_false_if_files_missing(self):
        self.database._get_current_version = MagicMock(return_value="1.2")
        self.database._missing_files = MagicMock(return_value=True)

        database_present = self.database._is_database_present("/path/to/database")

        self.assertFalse(database_present)
        self.assertIsNone(self.database.current_version)

    def test_is_database_present_set_current_version_and_return_true_if_database_found_and_no_files_missing(self):
        self.database._get_current_version = MagicMock(return_value="1.2")
        self.database._missing_files = MagicMock(return_value=False)

        database_present = self.database._is_database_present("/path/to/database")

        self.assertTrue(database_present)
        self.assertEqual(self.database.current_version, "1.2")

    def test_is_database_present_log_message_if_data_folder_not_found(self):
        self.database._get_current_version = MagicMock(return_value=None)

        self.database._is_database_present("path")

        self.database.output_manager.log_message.assert_called_once_with("No database found")

    def test_missing_files_look_for_required_files_in_database_directory(self):
        self.database.required_files = ['vane2_wordpress_meta.json', 'vane2_wordpress_versions.json']
        isfile = MagicMock()
        self.database.current_version = "1.2"

        with patch("vane.database.path.isfile", isfile):
            self.database._missing_files("/path/to/database")
            calls = isfile.call_args_list
            for call, file in zip(calls, self.database.required_files):
                args, kwargs = call
                self.assertIn("/path/to/database/vane2_data_1.2/%s" % file, args)

    def test_missing_files_return_false_if_no_file_missing(self):
        self.database.required_files = ['vane2_wordpress_meta.json', 'vane2_wordpress_versions.json']
        isfile = MagicMock(return_value=True)
        self.database.current_version = "1.2"

        with patch("vane.database.path.isfile", isfile):
            self.assertFalse(self.database._missing_files("/path/to/database"))

    def test_missing_files_return_true_if_files_missing(self):
        self.database.required_files = ['vane2_wordpress_meta.json', 'vane2_wordpress_versions.json']
        isfile = MagicMock(return_value=False)
        self.database.current_version = "1.2"

        with patch("vane.database.path.isfile", isfile):
            self.assertTrue(self.database._missing_files("/path/to/database"))

    def test_missing_files_log_missing_files(self):
        self.database.required_files = ["file.txt"]
        isfile = MagicMock(return_value=False)
        self.database.current_version = "1.2"

        with patch("vane.database.path.isfile", isfile):
            self.database._missing_files("/path/to/database")

            self.database.output_manager.log_message.assert_called_once_with("File file.txt is missing from database")

    @async_test()
    async def test_download_database_request_vane_data_of_latest_release(self):
        self.database.get_latest_release = make_mocked_coro(return_value={"tag_name": "2.0", "assets": [
            {'name': "vane2_data.tar.gz", 'url': "http://api_url/releases/assets/1"},
            {'name': "other_asset", 'url': "http://api_url/releases/assets/2"}]})

        await self.database.download_data_latest_release("path")

        self.database.aiohttp_session.get.assert_called_once_with("http://api_url/releases/assets/1", headers=ANY)

    @async_test()
    async def test_download_database_log_message_with_latest_version_before_download(self):
        self.database.get_latest_release = make_mocked_coro(return_value={"tag_name": "2.0", "assets": [
            {'name': "vane2_data.tar.gz", 'url': "http://api_url/releases/assets/1"}]})

        await self.database.download_data_latest_release("path")

        self.database.output_manager.log_message.assert_called_once_with("Downloading database version 2.0")

    @async_test()
    async def test_download_database_set_current_version_attribute_to_latest_version(self):
        self.database.get_latest_release = make_mocked_coro(return_value={"tag_name": "1.5", "assets": [
            {'name': "vane2_data.tar.gz", 'url': "http://api_url/releases/assets/1"}]})

        await self.database.download_data_latest_release("path")

        self.assertEqual(self.database.current_version, "1.5")

    @async_test()
    async def test_download_database_set_accept_header_of_request(self):
        self.database.get_latest_release = make_mocked_coro(return_value={"tag_name": "2.0", "assets": [
            {'name': "vane2_data.tar.gz", 'url': "http://api_url/releases/assets/1"}]})

        await self.database.download_data_latest_release("path")

        self.database.aiohttp_session.get.assert_called_once_with(ANY, headers={'accept': "application/octet-stream"})

    @async_test()
    async def test_download_database_cleanup_archive_file_after_extraction(self):
        self.database.get_latest_release = make_mocked_coro(return_value={"tag_name": "2.0", "assets": [
            {'name': "vane2_data.tar.gz", 'url': "http://api_url/releases/assets/1"}]})

        await self.database.download_data_latest_release("path")

        self.database.cleanup_archive_file.assert_called_once_with("path/vane2_data.tar.gz")

    @async_test()
    async def test_get_latest_release_make_latest_release_request_to_github_api(self):
        self.database.configure_update_repository("Owner", "database")

        await self.database.get_latest_release()

        self.database.aiohttp_session.get.assert_called_once_with(self.database.api_url + "/releases/latest")

    @async_test()
    async def test_get_latest_release_return_release(self):
        self.database.configure_update_repository("Owner", "database")
        self.response.json = make_mocked_coro(return_value={'tag_name': '1.0', 'id': "12345", 'assets': []})

        release = await self.database.get_latest_release()

        self.assertEqual(release, await self.response.json())

    def test_get_data_filename_return_archive_name_for_latest_release(self):
        database = Database(None)
        latest_release = {'tag_name': "1.0"}

        filename = database.get_data_archive_name(latest_release)

        self.assertEqual(filename, "vane2_data_1.0.tar.gz")

    def test_get_current_version_call_list_all_installed_database_versions(self):
        self.database._list_all_installed_database_versions = MagicMock()
        self.database._get_current_version("path/to/vane2/database")

        self.database._list_all_installed_database_versions.assert_called_once_with("path/to/vane2/database")

    def test_get_current_version_latest_version_if_multiple_versions_are_found(self):
        self.database._list_all_installed_database_versions = MagicMock(return_value=["vane2_data_1.0",
                                                                                      "vane2_data_1.1"])

        version = self.database._get_current_version("path")

        self.assertEqual(version, "1.1")

    def test_get_current_version_return_none_if_no_database_found(self):
        self.database._list_all_installed_database_versions = MagicMock(return_value=[])

        version = self.database._get_current_version("path")

        self.assertIsNone(version)

    def test_get_current_version_return_version_if_database_found(self):
        self.database._list_all_installed_database_versions = MagicMock(return_value=["vane2_data_1.2"])

        version = self.database._get_current_version("path")

        self.assertEqual(version, "1.2")

    def test_list_all_installed_database_versions_returns_database_directories_relative_names(self):
        directory_list = ["vane2_data_1.2", "vane2_data_1.3", "vane2_data_1.5"]
        self.glob_mock.return_value = list("/absolute_path/" + directory for directory in directory_list)
        self.database._get_latest_installed_version = MagicMock()

        self.database._get_current_version("/absolute_path")

        self.database._get_latest_installed_version.assert_called_once_with(directory_list)

    def test_list_all_installed_database_versions_search_in_database_path(self):
        self.database._list_all_installed_database_versions("path/to/vane2/database")

        self.glob_mock.assert_called_once_with("path/to/vane2/database/vane2_data_*")

    def test_list_all_installed_database_versions_dont_return_targz_database_files(self):
        directory_list = ["vane2_data_1.2", "vane2_data_1.2.tar.gz", "vane2_data_1.3.tar.gz"]
        self.glob_mock.return_value = directory_list

        database_directory_list = self.database._list_all_installed_database_versions("path/to/vane2/database")

        self.assertIn("vane2_data_1.2", database_directory_list)
        self.assertNotIn("vane2_data_1.2.tar.gz", database_directory_list)
        self.assertNotIn("vane2_data_1.3.tar.gz", database_directory_list)

    def test_get_latest_installed_version_return_latest_version_from_directory_name(self):
        database_directory = ["vane2_data_1.1", "vane2_data_1.2", "vane2_data_2.1"]

        latest_version = self.database._get_latest_installed_version(database_directory)

        self.assertEqual("2.1", latest_version)

    @freeze_time("2017-05-29")
    def test_get_days_since_last_update_return_time_in_days_between_now_and_database_folder_modification_time(self):
        database = Database(None)
        stat_result = MagicMock()
        stat_result.st_mtime = datetime(2017, 5, 24).timestamp()
        os_stat = MagicMock(return_value=stat_result)

        with patch('vane.database.stat', os_stat):
            days_since_last_update = database._get_days_since_last_update("path")

            self.assertEqual(days_since_last_update, 5)

    def test_cleanup_archive_file_remove_downloaded_archive_file(self):
        database = Database(None)
        fake_remove = MagicMock()
        with patch("vane.database.remove", fake_remove):

            database.cleanup_archive_file("filename.tar.gz")

            fake_remove.assert_called_once_with("filename.tar.gz")

    def test_get_database_directory_return_database_directory_based_on_current_version(self):
        self.database.current_version = "3.2"

        path = self.database._get_database_directory("/path/to/database")

        self.assertEqual(path, "/path/to/database/vane2_data_3.2")

    def test_get_database_directory_return_none_if_current_version_is_none(self):
        self.database.current_version = None

        path = self.database._get_database_directory("/path/to/database")

        self.assertIsNone(path)
