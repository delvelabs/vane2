from .versionidentification import VersionIdentification
from openwebvulndb.common.schemas import FileListGroupSchema
from os.path import join
import asyncio
from urllib.parse import urljoin
from .versionidentification import FetchedFile
from hammertime.ruleset import RejectRequest


class ActivePluginsFinder:

    def __init__(self, hammertime):
        self.hammertime = hammertime
        self.version_identification = VersionIdentification(hammertime)
        self.plugins_file_list = None
        self.popular_plugins_file_list = None
        self.vulnerable_plugins_file_list = None

    async def enumerate_popular_plugins(self, target):
        plugins = await self.enumerate_plugins(target, self.popular_plugins_file_list)
        return plugins

    async def enumerate_vulnerable_plugins(self, target):
        plugins = await self._enumerate_plugins(target, self.vulnerable_plugins_file_list)
        return plugins

    async def enumerate_all_plugins(self, target):
        plugins = await self._enumerate_plugins(target, self.plugins_file_list)
        return plugins

    async def _enumerate_plugins(self, target, plugins_file_list_group):
        plugins = []
        for file_list in plugins_file_list_group.file_lists:
            if len(file_list.files) > 0:
                self.version_identification.set_files_to_fetch(file_list)
                files = await self.version_identification.fetch_files(target)
                if len(files) > 0:
                    plugins.append(file_list.key)
        return plugins

    def load_plugins_files_signatures(self, file_path):
        with open(join(file_path, "vane2_popular_plugins_versions.json"), "r") as fp:
            self.popular_plugins_file_list, errors = FileListGroupSchema().loads(fp.read())
            if errors:
                raise Exception(errors)
        return
        with open(join(file_path, "vane2_vulnerable_plugins_versions.json"), "r") as fp:
            self.vulnerable_plugins_file_list, errors = FileListGroupSchema().loads(fp.read())
            if errors:
                raise Exception(errors)
        with open(join(file_path, "vane2_plugins_versions.json"), "r") as fp:
            self.plugins_file_list, errors = FileListGroupSchema().loads(fp.read())
            if errors:
                raise Exception(errors)

    async def enumerate_plugins(self, target, plugins_file_list_group):
        tasks_list = []
        for file_list in plugins_file_list_group.file_lists:
            if len(file_list.files) > 0:
                plugin_files_requests = self.request_plugin_files(target, file_list)
                tasks_list.append(plugin_files_requests)
        #done, pending = await asyncio.as_completed(tasks_list, loop=self.hammertime.loop)
        plugins = []
        for future in asyncio.as_completed(tasks_list, loop=self.hammertime.loop):
            try:
                plugin_key, files = await future
                if len(files) > 0:
                    plugins.append(plugin_key)
            except Exception:
                pass
        return plugins

    def request_plugin_files(self, target, file_list):
        requests = []
        for file in file_list.files:
            url = urljoin(target, file.path)
            arguments = {'file_path': file.path, 'hash_algo': file.signatures[0].algo}
            requests.append(self.hammertime.request(url, arguments=arguments))
        return self.hammertime.loop.create_task(self._request_plugin_files(file_list.key, requests))

    async def _request_plugin_files(self, plugin_key, files_requests):
        fetched_files = []
        done, pending = await asyncio.wait(files_requests, loop=self.hammertime.loop)
        for future in done:
            try:
                entry = await future
                if hasattr(entry.result, "hash"):
                    fetched_files.append(FetchedFile(path=entry.arguments["file_path"], hash=entry.result.hash))
            except RejectRequest:
                pass
        return plugin_key, fetched_files
