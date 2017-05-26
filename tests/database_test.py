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
        self.database.api_url = "https://api.github.com/repos/Owner/database"
        self.filename = "vane_data.tar.gz"
        self.database.aiohttp_session = MagicMock()
        self.database.aiohttp_session.get.return_value = AsyncContextManagerMock()

    def test_load_data_download_database_if_data_folder_not_found(self):
        self.database.download_data_latest_release = make_mocked_coro()
        isdir = MagicMock()
        with patch("vane.database.path.isdir", isdir):
            with loop_context() as loop:
                isdir.return_value = False
                self.database.loop = loop

                self.database.load_data("path")

                self.database.download_data_latest_release.assert_called_once_with("path")

    def test_load_data_download_database_if_files_missing(self):
        self.database.download_data_latest_release = make_mocked_coro()
        isdir = MagicMock()
        isfile = MagicMock()
        self.database.files_to_check = ['vane2_wordpress_meta.json', 'vane2_wordpress_versions.json']
        with patch("vane.database.path.isdir", isdir), patch("vane.database.path.isfile", isfile):
            with loop_context() as loop:
                isdir.return_value = True
                isfile.return_value = False
                self.database.loop = loop

                self.database.load_data("path")

                self.database.download_data_latest_release.assert_called_once_with("path")
                calls = isfile.call_args_list
                for call, file in zip(calls, self.database.files_to_check):
                    args, kwargs = call
                    self.assertIn("data/%s" % file, args)

    def test_load_database_dont_download_database_if_all_files_present(self):
        self.database.download_data_latest_release = make_mocked_coro()
        isdir = MagicMock()
        isfile = MagicMock()
        self.database.files_to_check = ['vane2_wordpress_meta.json', 'vane2_wordpress_versions.json']
        with patch("vane.database.path.isdir", isdir), patch("vane.database.path.isfile", isfile):
            with loop_context() as loop:
                isdir.return_value = True
                isfile.return_value = True
                self.database.loop = loop

                self.database.load_data("path")

                self.database.download_data_latest_release.assert_not_called()

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
