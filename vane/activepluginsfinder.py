from .versionidentification import VersionIdentification
from openwebvulndb.common.schemas import FileListGroupSchema
from os.path import join
import asyncio


class ActivePluginsFinder:

    def __init__(self, hammertime):
        self.hammertime = hammertime
        self.version_identification = VersionIdentification(hammertime)
        self.plugins_file_list = None
        self.popular_plugins_file_list = None
        self.vulnerable_plugins_file_list = None
        self.plugins_async_iterator = PluginAsyncIterator(asyncio.Queue(loop=self.hammertime.loop))

    async def enumerate_popular_plugins(self, target):
        plugins = await self._enumerate_plugins(target, self.popular_plugins_file_list)
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
        with open(join(file_path, "vane2_plugins_versions.json"), "r") as fp:
            self.plugins_file_list, errors = FileListGroupSchema().loads(fp.read())
            if errors:
                raise Exception(errors)

        with open(join(file_path, "vane2_popular_plugins_versions.json"), "r") as fp:
            self.popular_plugins_file_list, errors = FileListGroupSchema().loads(fp.read())
            if errors:
                raise Exception(errors)
        with open(join(file_path, "vane2_vulnerable_plugins_versions.json"), "r") as fp:
            self.vulnerable_plugins_file_list, errors = FileListGroupSchema().loads(fp.read())
            if errors:
                raise Exception(errors)


class PluginAsyncIterator:

    def __init__(self, queue):
        self.queue = queue

    async def __aiter__(self):
        return self

    async def __anext__(self):
        out = None
        if not self.queue.empty():
            out = self.queue.get_nowait()
        else:
            out = await self.queue.get()

        if out is None:
            raise StopAsyncIteration
        return out
