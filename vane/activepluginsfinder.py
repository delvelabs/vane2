from openwebvulndb.common.schemas import FileListGroupSchema
from os.path import join
import asyncio
from .filefetcher import FileFetcher


class ActivePluginsFinder:

    def __init__(self, hammertime, target_url):
        self.loop = hammertime.loop
        self.file_fetcher = FileFetcher(hammertime, target_url)

        self.plugins_file_list_group = None

    def load_plugins_files_signatures(self, file_path, popular, vulnerable):
        if popular:
            file_name = "vane2_popular_plugins_versions.json"
        elif vulnerable:
            file_name = "vane2_vulnerable_plugins_versions.json"
        else:
            file_name = "vane2_plugins_versions.json"

        with open(join(file_path, file_name), "r") as fp:
            self.plugins_file_list_group, errors = FileListGroupSchema().loads(fp.read())
            return errors

    async def enumerate_plugins(self):
        tasks_list = []
        errors = []

        for plugin_file_list in self.plugins_file_list_group.file_lists:
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
