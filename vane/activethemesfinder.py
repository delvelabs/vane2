# vane 2.0: A Wordpress vulnerability assessment tool.
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

from os.path import join
from openwebvulndb.common.schemas import FileListGroupSchema
from vane.filefetcher import FileFetcher
import asyncio


class ActiveThemesFinder:

    def __init__(self, hammertime, target_url):
        self.loop = hammertime.loop
        self.file_fetcher = FileFetcher(hammertime, target_url)

        self.themes_file_list_group = None

    def load_themes_files_signatures(self, file_path, popular_themes, vulnerable_themes):
        if popular_themes:
            file_name = "vane2_popular_themes_versions.json"
        elif vulnerable_themes:
            file_name = "vane2_vulnerable_themes_versions.json"
        else:
            file_name = "vane2_themes_versions.json"

        with open(join(file_path, file_name), "r") as fp:
            self.themes_file_list_group, errors = FileListGroupSchema().loads(fp.read())
            return errors

    async def enumerate_themes(self):
        tasks_list = []
        errors = []

        for themes_file_list in self.themes_file_list_group.file_lists:
            if len(themes_file_list.files) > 0:
                theme_files_requests = self.file_fetcher.request_files(themes_file_list.key, themes_file_list)
                tasks_list.append(theme_files_requests)

        themes = []
        for future in asyncio.as_completed(tasks_list, loop=self.loop):
            try:
                theme_key, fetched_files = await future
                if len(fetched_files) > 0:
                    themes.append({'key': theme_key, 'files': fetched_files})
            except Exception as e:
                errors.append(e)
        return themes, errors
