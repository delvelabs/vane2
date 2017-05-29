from os import path
import tarfile
import re
import glob
from openwebvulndb.common.version import VersionCompare
from packaging.version import parse

vane2_data_directory_pattern = re.compile("vane2_data_\d+\.\d+$")


class Database:

    def __init__(self, loop=None):
        self.loop = loop
        self.files_to_check = []
        self.api_url = None

    def load_data(self, database_path):
        if self.is_update_required(database_path):
            self.loop.run_until_complete(self.download_data_latest_release(database_path))

    def is_update_required(self, database_path):
        current_version = self.get_current_database_version(database_path)
        if current_version is None:
            return True
        if self.get_days_since_last_update(database_path) > self.auto_update_frequency:
            latest_version = self.loop.run_until_complete(self.get_latest_release())['tag_name']
            if parse(latest_version) > parse(current_version):
                return True
        return self.missing_files(database_path, current_version)

    def missing_files(self, database_path, current_version):
        for file in self.files_to_check:
            if not path.isfile("{0}/{1}".format(path.join(database_path, "vane2_data_%s" % current_version), file)):
                return True
        return False

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

    def get_current_database_version(self, database_path):
        database_dir = glob.glob(database_path + "/vane2_data_*")
        directory_list = [directory[directory.rfind("/") + 1:] for directory in database_dir if vane2_data_directory_pattern.search(directory)]
        if len(directory_list) == 0:
            return None
        else:
            return self.get_latest_installed_version(directory_list)

    def get_latest_installed_version(self, installed_directory_list):
        versions = []
        version_pattern = re.compile("\d+\.\d+")
        for directory in installed_directory_list:
            versions.append(version_pattern.search(directory).group())
        sorted_versions = VersionCompare.sorted(versions)
        return sorted_versions[-1]
