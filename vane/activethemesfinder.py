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
from hammertime.ruleset import RejectRequest


class ActiveThemesFinder:

    def __init__(self, hammertime, target_url):
        self.loop = hammertime.loop
        self.file_fetcher = FileFetcher(hammertime, target_url)

        self.themes_file_list_group = None

    def load_themes_files_signatures(self, file_path, popular_themes, vulnerable_themes):
        def append_to_file_list_group(file_list_group):
            for theme_file_list in file_list_group.file_lists:
                if theme_file_list.key not in (file_list.key for file_list in self.themes_file_list_group.file_lists):
                    self.themes_file_list_group.file_lists.append(theme_file_list)

        def load(file_name, merge_if_exists=False):
            with open(join(file_path, file_name), "r") as fp:
                if self.themes_file_list_group is not None and merge_if_exists:
                    data, _errors = FileListGroupSchema().loads(fp.read())
                    append_to_file_list_group(data)
                else:
                    self.themes_file_list_group, _errors = FileListGroupSchema().loads(fp.read())
                return _errors

        if popular_themes:
            errors = load("vane2_popular_themes_versions.json")
            if errors:
                return errors
        if vulnerable_themes:
            errors = load("vane2_vulnerable_themes_versions.json", True)
        if not vulnerable_themes and not popular_themes:
            errors = load("vane2_themes_versions.json")
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
            except RejectRequest as e:
                errors.append(e)
        return themes, errors
