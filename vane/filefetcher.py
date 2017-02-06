import asyncio
from collections import namedtuple
from hammertime.ruleset import RejectRequest
from urllib.parse import urljoin


FetchedFile = namedtuple('FetchedFile', ['path', 'hash'])


class FileFetcher:

    def __init__(self, hammertime, url):
        self.hammertime = hammertime
        self.url = url

    def request_files(self, key, file_list, suppress_rejected_requests=True):
        requests = []
        for file in file_list.files:
            url = urljoin(self.url, file.path)
            arguments = {'file_path': file.path, 'hash_algo': file.signatures[0].algo}
            requests.append(self.hammertime.request(url, arguments=arguments))
        return self.hammertime.loop.create_task(self._request_files(key, requests, suppress_rejected_requests))

    async def _request_files(self, key, requests, suppress_rejected_requests):
        fetched_files = []
        done, pending = await asyncio.wait(requests, loop=self.hammertime.loop)
        for future in done:
            try:
                entry = await future
                if hasattr(entry.result, "hash"):
                    fetched_files.append(FetchedFile(path=entry.arguments["file_path"], hash=entry.result.hash))
            except RejectRequest as rejected_request:
                if not suppress_rejected_requests:
                    raise rejected_request
        return key, fetched_files
