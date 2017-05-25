from unittest import TestCase
from unittest.mock import patch, MagicMock
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
        self.database.api_url = "https://api.github.com/repos/Owner/database/"

    def test_load_data_download_database_if_data_folder_not_found(self):
        self.database.download_data_latest_release = make_mocked_coro()
        isdir = MagicMock()
        with patch("vane.database.path.isdir", isdir):
            with loop_context() as loop:
                isdir.return_value = False
                self.database.loop = loop

                self.database.load_data()

                self.database.download_data_latest_release.assert_called_once_with()

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

                self.database.load_data()

                self.database.download_data_latest_release.assert_called_once_with()
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

                self.database.load_data()

                self.database.download_data_latest_release.assert_not_called()

    @async_test()
    async def test_download_database_request_zip_of_latest_release(self, loop):
        self.database.aiohttp_session = MagicMock()
        self.database.aiohttp_session.get = AsyncContextManagerMock()
        self.database.get_latest_release = make_mocked_coro(
            return_value={"assets_url": self.database.api_url + "/releases/release_id/assets"})

        await self.database.download_data_latest_release()

        self.database.aiohttp_session.get.assert_called_once_with(self.database.api_url + "/releases/release_id/assets")



