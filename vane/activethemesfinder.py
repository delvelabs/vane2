from os.path import join
from openwebvulndb.common.schemas import FileListGroupSchema
from vane.filefetcher import FileFetcher
import asyncio


class ActiveThemesFinder:

    def __init__(self, hammertime, target_url):
        self.loop = hammertime.loop
        self.file_fetcher = FileFetcher(hammertime, target_url)

        self.themes_file_list_group = None

    def load_themes_files_signatures(self, file_path, popular_themes, vulnerable_themes):
        if popular_themes:
            file_name = "vane2_popular_themes_versions.json"
        elif vulnerable_themes:
            file_name = "vane2_vulnerable_themes_versions.json"
        else:
            file_name = "vane2_themes_versions.json"

        with open(join(file_path, file_name), "r") as fp:
            self.themes_file_list_group, errors = FileListGroupSchema().loads(fp.read())
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
            except Exception as e:
                errors.append(e)
        return themes, errors
