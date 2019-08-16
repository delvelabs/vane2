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

import asyncio
from collections import namedtuple
from hammertime.ruleset import StopRequest, RejectRequest
from hammertime.rules.deadhostdetection import OfflineHostException
from urllib.parse import urljoin


FetchedFile = namedtuple('FetchedFile', ['path', 'hash'])


class FileFetcher:

    def __init__(self, hammertime, url):
        self.hammertime = hammertime
        self.url = url
        self.timeouts = 0

    def request_files(self, key, file_list):
        self.timeouts = 0
        hammertime_requests = []
        for file in file_list.files:
            url = urljoin(self.url, file.path)
            expected_hash = self._get_expected_hash(file)
            arguments = {"file_path": file.path, "hash_algo": file_list.hash_algo, "expected_hash": expected_hash,
                         "expected_status_code": 200}
            hammertime_requests.append(self.hammertime.request(url, arguments=arguments))
        return self.hammertime.loop.create_task(self._request_files(key, hammertime_requests))

    async def _request_files(self, key, hammertime_requests):
        fetched_files = []
        done, pending = await asyncio.wait(hammertime_requests, loop=self.hammertime.loop)
        for future in done:
            try:
                entry = await future
                if entry is not None and hasattr(entry.result, "hash"):
                    fetched_files.append(FetchedFile(path=entry.arguments["file_path"], hash=entry.result.hash))
            except OfflineHostException:
                raise
            except StopRequest:
                self.timeouts += 1
            except RejectRequest:
                pass
        return key, fetched_files

    def _get_expected_hash(self, file):
        hash = set()
        for signature in file.signatures:
            hash.add(signature.hash)
        return hash
