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