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

import json
from openwebvulndb.common.schemas import FileListSchema
import asyncio
from urllib.parse import urljoin
from collections import namedtuple
from openwebvulndb.common.version import VersionCompare
from hammertime.ruleset import RejectRequest


FetchedFile = namedtuple('FetchedFile', ['path', 'hash'])


class VersionIdentification:

    def __init__(self, hammertime):
        self.file_list = None
        self.hammertime = hammertime

    def load_files_signatures(self, filename):
        with open(filename, "rt") as fp:
            schema = FileListSchema()
            data, errors = schema.load(json.load(fp))
            if errors:
                raise Exception(errors)
            self.file_list = data

    async def identify_version(self, target):
        fetched_files = await self.fetch_files(target)

        possible_versions = self._get_possible_versions(fetched_files)

        if len(possible_versions) > 1:
            return self._get_lowest_version(possible_versions)
        elif len(possible_versions) == 1:
            return possible_versions.pop()
        return None

    def _get_lowest_version(self, versions):
        sorted_versions = VersionCompare.sorted(versions)
        return sorted_versions[0]

    async def fetch_files(self, target):
        requests = []
        for file in self.get_files_to_fetch():
            url = urljoin(target, file.path)
            arguments = {'file_path': file.path, 'hash_algo': file.signatures[0].algo}
            requests.append(self.hammertime.request(url, arguments=arguments))

        fetched_files = []
        done, pending = await asyncio.wait(requests, loop=self.hammertime.loop)
        for future in done:
            try:
                entry = await future
                if hasattr(entry.result, 'hash'):
                    fetched_files.append(FetchedFile(path=entry.arguments['file_path'], hash=entry.result.hash))
            except RejectRequest:
                pass
        return fetched_files

    def get_files_to_fetch(self):
        for file in self.file_list.files:
            yield file

    def set_files_to_fetch(self, file_list):
        self.file_list = file_list

    def _get_possible_versions(self, fetched_files):
        possible_versions = set()
        for file in fetched_files:
            versions = self._get_possible_versions_for_fetched_file(file)
            if versions is not None:
                if len(possible_versions) > 0:
                    possible_versions &= set(versions)
                else:
                    possible_versions = set(versions)
        return possible_versions

    def _get_possible_versions_for_fetched_file(self, fetched_file):
        file = self._get_file_from_file_list(fetched_file.path)
        if file is not None:
            signatures = file.signatures
            for signature in signatures:
                if fetched_file.hash == signature.hash:
                    return signature.versions
        return None

    def _get_file_from_file_list(self, file_path):
        for file in self.get_files_to_fetch():
            if file.path == file_path:
                return file
        return None
