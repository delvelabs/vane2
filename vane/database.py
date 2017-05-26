from os import path
import tarfile
import re


class Database:

    def __init__(self, loop=None):
        self.loop = loop
        self.files_to_check = []
        self.api_url = None

    def load_data(self, database_path):
        missing_file = False
        if path.isdir(database_path + "/vane2_data"):
            for file in self.files_to_check:
                if not path.isfile("{0}/{1}".format("data", file)):
                    missing_file = True
                    break
            if missing_file:
                self.loop.run_until_complete(self.download_data_latest_release(database_path))

        else:
            self.loop.run_until_complete(self.download_data_latest_release(database_path))

    async def download_data_latest_release(self, database_path):
        latest_release = await self.get_latest_release()
        data_filename = self.get_data_filename(latest_release)
        asset_url = None
        for asset in latest_release['assets']:
            if asset['name'] == data_filename:
                asset_url = asset['url']
        headers = {'accept': "application/octet-stream"}
        async with self.aiohttp_session.get(asset_url, headers=headers) as response:
            print(response.status)
            data = await response.read()
            self.save_data_to_file(data, path.join(database_path, data_filename))
            self.extract_downloaded_files(path.join(database_path, data_filename))

    async def get_latest_release(self):
        async with self.aiohttp_session.get(self.api_url + "/releases/latest") as response:
            return await response.json()

    def get_data_filename(self, latest_release):
        version = latest_release['tag_name']
        return "vane2_data_%s.tar.gz" % version

    def save_data_to_file(self, data, filename):
        with open(filename, 'wb') as file:
            file.write(data)

    def extract_downloaded_files(self, archive_filename):
        with tarfile.open(archive_filename, 'r:gz') as archive:
            archive.extractall(re.sub("\.tar\.gz$", "", archive_filename))
