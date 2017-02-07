from os.path import join
from openwebvulndb.common.schemas import FileListGroupSchema
from vane.filefetcher import FileFetcher
import asyncio


class ActiveThemesFinder:

    def __init__(self, hammertime, target_url):
        self.loop = hammertime.loop
        self.file_fetcher = FileFetcher(hammertime, target_url)

        self.themes_file_list = None
        self.popular_themes_file_list = None
        self.vulnerable_themes_file_list = None

    def load_themes_files_signatures(self, file_path):
        with open(join(file_path, "vane2_popular_themes_versions.json"), "r") as fp:
            self.popular_themes_file_list, errors = FileListGroupSchema().loads(fp.read())
            if errors:
                raise Exception(errors)
        with open(join(file_path, "vane2_vulnerable_themes_versions.json"), "r") as fp:
            self.vulnerable_themes_file_list, errors = FileListGroupSchema().loads(fp.read())
            if errors:
                raise Exception(errors)
        with open(join(file_path, "vane2_themes_versions.json"), "r") as fp:
            self.themes_file_list, errors = FileListGroupSchema().loads(fp.read())
            if errors:
                raise Exception(errors)

    async def enumerate_popular_themes(self):
        themes, errors = await self.enumerate_themes(self.popular_themes_file_list)
        return themes, errors

    async def enumerate_vulnerable_themes(self):
        themes, errors = await self.enumerate_themes(self.vulnerable_themes_file_list)
        return themes, errors

    async def enumerate_all_themes(self):
        themes, errors = await self.enumerate_themes(self.themes_file_list)
        return themes, errors

    async def enumerate_themes(self, themes_file_list_group):
        tasks_list = []
        errors = []

        for themes_file_list in themes_file_list_group.file_lists:
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
