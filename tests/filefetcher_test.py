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

from unittest import TestCase
from unittest.mock import MagicMock
from vane.filefetcher import FileFetcher
from hammertime import HammerTime
from aiohttp.test_utils import make_mocked_coro, loop_context
import asyncio
from openwebvulndb.common.models import File, FileSignature, FileList


class TestFileFetcher(TestCase):

    def test_request_files_return_task_wrapping_hammertime_requests(self):
        with loop_context() as loop:
            hammertime = HammerTime()
            hammertime.loop = loop
            hammertime.request_engine.perform = self.fake_perform
            fetcher = FileFetcher(hammertime, "www.example.com")
            signatures = [FileSignature(algo="SHA256", hash="hash")]
            plugin_key = "my-plugin"
            files_to_fetch = FileList(key=plugin_key, producer="", files=[
                              File(path="wp-content/plugins/my-plugin/script.js", signatures=signatures),
                              File(path="wp-content/plugins/my-plugin/style.css", signatures=signatures),
                              File(path="wp-content/plugins/my-plugin/readme.txt", signatures=signatures)])

            files_request = fetcher.request_files(plugin_key, files_to_fetch)

            key, fetched_files = loop.run_until_complete(asyncio.wait_for(files_request, None, loop=loop))
            self.assertEqual(key, plugin_key)
            for file in fetched_files:
                self.assertIn(file.path, [file.path for file in files_to_fetch.files])
                self.assertEqual(file.hash, "fake-hash")

    @staticmethod
    async def fake_perform(entry, *args, **kwargs):
        entry.result.hash = "fake-hash"
        return entry