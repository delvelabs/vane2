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

from openwebvulndb.common.schemas import FileListGroupSchema
from os.path import join
import asyncio
from .filefetcher import FileFetcher


class ActivePluginsFinder:

    def __init__(self, hammertime, target_url):
        self.loop = hammertime.loop
        self.file_fetcher = FileFetcher(hammertime, target_url)

        self.plugins_file_list_group = None

    def load_plugins_files_signatures(self, file_path, popular, vulnerable):
        def merge_to_file_list_group(file_list_group):
            for plugin_file_list in file_list_group.file_lists:
                if plugin_file_list.key not in (file_list.key for file_list in self.plugins_file_list_group.file_lists):
                    self.plugins_file_list_group.file_lists.append(plugin_file_list)

        def load(file_name, merge_if_exists=False):
            with open(join(file_path, file_name), "r") as fp:
                if self.plugins_file_list_group is not None and merge_if_exists:
                    data, _errors = FileListGroupSchema().loads(fp.read())
                    merge_to_file_list_group(data)
                else:
                    self.plugins_file_list_group, _errors = FileListGroupSchema().loads(fp.read())
                return _errors

        if popular:
            errors = load("vane2_popular_plugins_versions.json")
            if errors:
                return errors
        if vulnerable:
            errors = load("vane2_vulnerable_plugins_versions.json", True)
        if not vulnerable and not popular:
            errors = load("vane2_plugins_versions.json")
        return errors

    async def enumerate_plugins(self):
        tasks_list = []
        errors = []

        for plugin_file_list in self.plugins_file_list_group.file_lists:
            if len(plugin_file_list.files) > 0:
                plugin_files_requests = self.file_fetcher.request_files(plugin_file_list.key, plugin_file_list)
                tasks_list.append(plugin_files_requests)

        plugins = []
        for future in asyncio.as_completed(tasks_list, loop=self.loop):
            try:
                plugin_key, fetched_files = await future
                if len(fetched_files) > 0:
                    plugins.append({'key': plugin_key, 'files': fetched_files})
            except Exception as e:
                errors.append(e)
        return plugins, errors
