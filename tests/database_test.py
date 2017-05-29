from unittest import TestCase
from unittest.mock import patch, MagicMock, ANY
from vane.database import Database
from aiohttp.test_utils import make_mocked_coro, loop_context
from fixtures import async_test, AsyncContextManagerMock


#auto update à tous les x jours (conserve la date de la dernière update)
#download le dernier tarzip, le unpack dans un folder et met à jour la date d'update
#si pas de database trouvée, fait le download.
#os.stat pour la date de modif du fichier (ou utiliser la date de publication de la dernière update).
class TestDatabase(TestCase):

    def setUp(self):
        self.database = Database()
        self.database.auto_update_frequency = 7
        self.database.get_days_since_last_update = MagicMock(return_value=8)
        self.database.api_url = "https://api.github.com/repos/Owner/database"
        self.filename = "vane_data.tar.gz"
        self.database.aiohttp_session = MagicMock()
        self.database.aiohttp_session.get.return_value = AsyncContextManagerMock()

    def test_load_database_download_database_if_update_required(self):
        self.database.download_data_latest_release = make_mocked_coro()
        self.database.is_update_required = MagicMock(return_value=True)
        with loop_context() as loop:
            self.database.loop = loop

            self.database.load_data("path")

            self.database.download_data_latest_release.assert_called_once_with("path")

    def test_is_update_required_return_true_if_data_folder_not_found(self):
        self.database.get_current_database_version = MagicMock(return_value=None)
        with loop_context() as loop:
            self.database.loop = loop

            self.assertTrue(self.database.is_update_required("path"))

    def test_is_update_required_return_true_if_files_missing(self):
        self.database.get_current_database_version = MagicMock(return_value="1.0")
        self.database.get_latest_release = make_mocked_coro(
            return_value={'tag_name': '1.0', 'id': "12345", 'assets': []})
        self.database.missing_files = MagicMock(return_value=True)
        with loop_context() as loop:
            self.database.loop = loop

            self.assertTrue(self.database.is_update_required("path"))

    def test_is_update_required_return_false_if_no_files_missing(self):
        self.database.get_current_database_version = MagicMock(return_value="1.0")
        self.database.get_latest_release = make_mocked_coro(
            return_value={'tag_name': '1.0', 'id': "12345", 'assets': []})
        self.database.missing_files = MagicMock(return_value=False)
        with loop_context() as loop:
            self.database.loop = loop

            self.assertFalse(self.database.is_update_required("path"))

    def test_is_update_required_return_true_if_installed_version_is_not_latest_version(self):
        with loop_context() as loop:
            self.database.loop = loop
            self.database.get_current_database_version = MagicMock(return_value="1.0")
            self.database.get_latest_release = make_mocked_coro(return_value={'tag_name': '2.0', 'id': "12345", 'assets': []})

            self.assertTrue(self.database.is_update_required("path"))

    def test_is_update_required_return_false_if_installed_version_is_latest_version(self):
        with loop_context() as loop:
            self.database.loop = loop
            self.database.get_current_database_version = MagicMock(return_value="1.0")
            self.database.get_latest_release = make_mocked_coro(return_value={'tag_name': '1.0', 'id': "12345", 'assets': []})

            self.assertFalse(self.database.is_update_required("path"))

    def test_is_update_required_check_if_new_version_available_if_last_update_older_than_auto_update_frequency(self):
        self.database.auto_update_frequency = 7
        self.database.get_days_since_last_update = MagicMock(return_value=8)
        self.database.get_current_database_version = MagicMock(return_value="1.0")
        self.database.missing_files = MagicMock(return_value=False)
        self.database.get_latest_release = make_mocked_coro(return_value={'tag_name': '1.0', 'id': "12345", 'assets': []})
        with loop_context() as loop:
            self.database.loop = loop

            self.database.is_update_required("path")

            self.database.get_latest_release.assert_called_once_with()

    def test_is_update_required_dont_check_if_new_version_available_if_last_update_newer_than_auto_update_frequency(self):
        self.database.auto_update_frequency = 7
        self.database.get_days_since_last_update = MagicMock(return_value=6)
        self.database.get_current_database_version = MagicMock(return_value="1.0")
        self.database.missing_files = MagicMock(return_value=False)
        self.database.get_latest_release = make_mocked_coro(return_value={'tag_name': '1.0', 'id': "12345", 'assets': []})
        with loop_context() as loop:
            self.database.loop = loop

            self.database.is_update_required("path")

            self.database.get_latest_release.assert_not_called()

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

        self.database.aiohttp_session.get.assert_called_once_with(self.database.api_url + "/releases/assets/1", headers=ANY)

    @async_test()
    async def test_download_database_set_accept_header_of_request(self):
        self.database.get_latest_release = make_mocked_coro(return_value={"assets": [
            {'name': "vane2_data.tar.gz", 'url': self.database.api_url + "/releases/assets/1"}]})
        self.database.get_data_filename = MagicMock(return_value="vane2_data.tar.gz")

        await self.database.download_data_latest_release("path")

        self.database.aiohttp_session.get.assert_called_once_with(ANY, headers={'accept': "application/octet-stream"})

    @async_test()
    async def test_get_latest_release_make_latest_release_request_to_github_api(self):
        await self.database.get_latest_release()

        self.database.aiohttp_session.get.assert_called_once_with(self.database.api_url + "/releases/latest")

    @async_test()
    async def test_get_latest_release_return_release(self):
        response = MagicMock()
        response.json = make_mocked_coro(return_value={'tag_name': '1.0', 'id': "12345", 'assets': []})
        self.database.aiohttp_session.get.return_value.aenter_return = response

        release = await self.database.get_latest_release()

        self.assertEqual(release, await response.json())

    def test_get_data_filename_return_basename_and_latest_release_version(self):
        latest_release = {'tag_name': "1.0"}

        filename = self.database.get_data_filename(latest_release)

        self.assertEqual(filename, "vane2_data_1.0.tar.gz")

    def test_get_current_database_version_search_in_database_path(self):
        fake_glob = MagicMock()
        glob_patch = patch("vane.database.glob.glob", fake_glob)
        glob_patch.start()

        self.database.get_current_database_version("path/to/vane2/database")

        fake_glob.assert_called_once_with("path/to/vane2/database/vane2_data_*")

        glob_patch.stop()

    def test_get_current_database_version_latest_version_if_multiple_versions_are_found(self):
        fake_glob = MagicMock(return_value=["vane2_data_1.0", "vane2_data_1.1"])
        glob_patch = patch("vane.database.glob.glob", fake_glob)
        glob_patch.start()

        version = self.database.get_current_database_version("path")

        self.assertEqual(version, "1.1")

        glob_patch.stop()

    def test_get_current_database_version_return_none_if_no_database_found(self):
        fake_glob = MagicMock(return_value=[])
        glob_patch = patch("vane.database.glob.glob", fake_glob)
        glob_patch.start()

        version = self.database.get_current_database_version("path")

        self.assertIsNone(version)

        glob_patch.stop()

    def test_get_current_database_version_return_version_if_database_found(self):
        fake_glob = MagicMock(return_value=["vane2_data_1.2"])
        glob_patch = patch("vane.database.glob.glob", fake_glob)
        glob_patch.start()

        version = self.database.get_current_database_version("path")

        self.assertEqual(version, "1.2")

        glob_patch.stop()

    def test_get_current_version_calls_get_latest_installed_version_with_database_directories_relative_names(self):
        directory_list = ["vane2_data_1.2", "vane2_data_1.3", "vane2_data_1.5"]
        fake_glob = MagicMock(return_value=list("/absolute_path/" + directory for directory in directory_list))
        glob_patch = patch("vane.database.glob.glob", fake_glob)
        glob_patch.start()
        self.database.get_latest_installed_version = MagicMock()

        self.database.get_current_database_version("/absolute_path")

        self.database.get_latest_installed_version.assert_called_once_with(directory_list)

        glob_patch.stop()

    def test_get_current_version_dont_pass_targz_database_files_to_get_latest_installed_version(self):
        directory_list = ["vane2_data_1.2", "vane2_data_1.2.tar.gz", "vane2_data_1.3.tar.gz"]
        fake_glob = MagicMock(return_value=directory_list)
        glob_patch = patch("vane.database.glob.glob", fake_glob)
        glob_patch.start()
        self.database.get_latest_installed_version = MagicMock()

        self.database.get_current_database_version("path")

        self.database.get_latest_installed_version.assert_called_once_with(["vane2_data_1.2"])

        glob_patch.stop()

    def test_get_latest_installed_version_return_latest_version_from_directory_name(self):
        database_directory = ["vane2_data_1.1", "vane2_data_1.2", "vane2_data_2.1"]

        latest_version = self.database.get_latest_installed_version(database_directory)

        self.assertEqual("2.1", latest_version)

