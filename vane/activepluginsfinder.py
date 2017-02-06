from openwebvulndb.common.schemas import FileListGroupSchema
from os.path import join
import asyncio
from .filefetcher import FileFetcher


class ActivePluginsFinder:

    def __init__(self, hammertime, target_url):
        self.loop = hammertime.loop
        self.file_fetcher = FileFetcher(hammertime, target_url)

        self.plugins_file_list = None
        self.popular_plugins_file_list = None
        self.vulnerable_plugins_file_list = None

    async def enumerate_popular_plugins(self):
        plugins, errors = await self.enumerate_plugins(self.popular_plugins_file_list)
        return plugins, errors

    async def enumerate_vulnerable_plugins(self):
        plugins, errors = await self.enumerate_plugins(self.vulnerable_plugins_file_list)
        return plugins, errors

    async def enumerate_all_plugins(self):
        plugins, errors = await self.enumerate_plugins(self.plugins_file_list)
        return plugins, errors

    def load_plugins_files_signatures(self, file_path):
        with open(join(file_path, "vane2_popular_plugins_versions.json"), "r") as fp:
            self.popular_plugins_file_list, errors = FileListGroupSchema().loads(fp.read())
            if errors:
                raise Exception(errors)
        # with open(join(file_path, "vane2_vulnerable_plugins_versions.json"), "r") as fp:
        #     self.vulnerable_plugins_file_list, errors = FileListGroupSchema().loads(fp.read())
        #     if errors:
        #         raise Exception(errors)
        # with open(join(file_path, "vane2_plugins_versions.json"), "r") as fp:
        #     self.plugins_file_list, errors = FileListGroupSchema().loads(fp.read())
        #     if errors:
        #         raise Exception(errors)

    async def enumerate_plugins(self, plugins_file_list_group):
        tasks_list = []
        errors = []

        for plugin_file_list in plugins_file_list_group.file_lists:
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
