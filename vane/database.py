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

from os import path, stat, remove
import tarfile
import re
import glob
from openwebvulndb.common.version import VersionCompare
from packaging.version import parse
from datetime import datetime
from aiohttp import ClientError

vane2_data_directory_pattern = re.compile("vane2_data_\d+\.\d+$")


class Database:

    ALWAYS_CHECK_FOR_UPDATE = -1
    files_in_database = ["vane2_plugins_meta.json", "vane2_vulnerability_database.json", "vane2_plugins_versions.json",
                         "vane2_vulnerable_plugins_versions.json", "vane2_popular_plugins_versions.json",
                         "vane2_vulnerable_themes_versions.json", "vane2_popular_themes_versions.json",
                         "vane2_wordpress_meta.json", "vane2_themes_meta.json", "vane2_wordpress_versions.json",
                         "vane2_themes_versions.json"]

    def __init__(self, output_manager, loop=None, aiohttp_session=None, auto_update_frequency=7):
        self.loop = loop
        self.files_to_check = Database.files_in_database
        self.api_url = None
        self.auto_update_frequency = auto_update_frequency
        self.aiohttp_session = aiohttp_session
        self.current_version = None
        self.database_path = None
        self.output_manager = output_manager

    def configure_update_repository(self, repository_owner, repository_name):
        self.api_url = "https://api.github.com/repos/{0}/{1}".format(repository_owner, repository_name)

    def load_data(self, database_path, no_update=False):
        try:
            if self.is_update_required(database_path, no_update=no_update):
                self.loop.run_until_complete(self.download_data_latest_release(database_path))
                self.output_manager.log_message("Database update done")
        except (ClientError, AssertionError) as e:
            if self.current_version is not None:
                self.database_path = self._get_database_path(database_path)
            raise e
        self.database_path = self._get_database_path(database_path)

    def is_update_required(self, database_path, no_update=False):
        self.current_version = self.get_current_version(database_path)
        if self.current_version is None:
            self.output_manager.log_message("No database found")
            return True
        if not no_update and self.get_days_since_last_update(database_path) > self.auto_update_frequency:
            latest_release = self.loop.run_until_complete(self.get_latest_release())
            latest_version = latest_release['tag_name']
            if parse(latest_version) > parse(self.current_version):
                self.output_manager.log_message("New database version available: %s" % latest_version)
                return True
            else:
                self.output_manager.log_message("Database version is latest version available")
        return self.missing_files(database_path)

    def missing_files(self, database_path):
        for file in self.files_to_check:
            if not path.isfile(path.join(self._get_database_path(database_path), file)):
                self.output_manager.log_message("File %s is missing from database" % file)
                return True
        return False

    async def download_data_latest_release(self, database_path):
        latest_release = await self.get_latest_release()
        self.output_manager.log_message("Downloading database version %s" % latest_release['tag_name'])
        archive_filename = self.get_data_archive_name(latest_release)
        asset_url = None
        for asset in latest_release['assets']:
            if asset['name'] == archive_filename:
                asset_url = asset['url']
        headers = {'accept': "application/octet-stream"}
        async with self.aiohttp_session.get(asset_url, headers=headers) as response:
            assert response.status == 200
            data = await response.read()
            data_archive_path = path.join(database_path, archive_filename)
            self.save_data_to_file(data, data_archive_path)
            self.extract_downloaded_files(data_archive_path)
            self.cleanup_archive_file(data_archive_path)
            self.current_version = latest_release['tag_name']

    async def get_latest_release(self):
        async with self.aiohttp_session.get(self.api_url + "/releases/latest") as response:
            assert response.status == 200
            return await response.json()

    def get_data_archive_name(self, latest_release):
        version = latest_release['tag_name']
        return "vane2_data_%s.tar.gz" % version

    def save_data_to_file(self, data, filename):
        with open(filename, 'wb') as file:
            file.write(data)

    def extract_downloaded_files(self, archive_filename):
        with tarfile.open(archive_filename, 'r:gz') as archive:
            archive.extractall(re.sub("\.tar\.gz$", "", archive_filename))

    def cleanup_archive_file(self, archive_filename):
        remove(archive_filename)

    def get_current_version(self, database_path):
        database_dir = glob.glob(database_path + "/vane2_data_*")
        directory_list = []
        for abs_directory_path in database_dir:
            if vane2_data_directory_pattern.search(abs_directory_path):
                directory_name = abs_directory_path[abs_directory_path.rfind("/") + 1:]
                directory_list.append(directory_name)
        if len(directory_list) == 0:
            return None
        else:
            self.current_version = self.get_latest_installed_version(directory_list)
            return self.current_version

    def get_latest_installed_version(self, installed_directory_list):
        versions = []
        version_pattern = re.compile("\d+\.\d+")
        for directory in installed_directory_list:
            versions.append(version_pattern.search(directory).group())
        sorted_versions = VersionCompare.sorted(versions)
        return sorted_versions[-1]

    def get_days_since_last_update(self, vane_data_path):
        last_update_date_in_seconds = stat(vane_data_path).st_mtime
        last_update_date = datetime.fromtimestamp(last_update_date_in_seconds)
        now = datetime.now()
        elapsed_days = now - last_update_date
        return elapsed_days.days

    def _get_database_path(self, database_path):
        directory_name = "vane2_data_%s" % self.current_version
        return path.join(database_path, directory_name)
