from .versionidentification import VersionIdentification
from openwebvulndb.common.schemas import FileListGroupSchema
import json


class ActivePluginsFinder:

    def __init__(self, hammertime):
        self.version_identification = VersionIdentification(hammertime)
        self.plugins_file_list = None

    async def enumerate_plugins(self, target):
        plugins = []
        for file_list in self.plugins_file_list.file_lists:
            if len(file_list.files) > 0:
                self.version_identification.set_files_to_fetch(file_list)
                files = await self.version_identification.fetch_files(target)
                if files:
                    plugins.append(file_list.key)
        return plugins

    def load_plugins_files_signatures(self, filename):
        with open(filename, "r") as fp:
            self.plugins_file_list, errors = FileListGroupSchema().loads(fp.read())
            if errors:
                raise Exception(errors)
