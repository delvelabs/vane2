import hashlib
import json
from common.schemas import VersionListSchema


class VersionIdentification:

    def __init__(self, hammertime):
        # version list comes from openwebvulndb
        self.versions_list = None
        self.signatures_files = []
        self.hammertime = hammertime

    def load_versions_signatures(self, filename):
        with open(filename, "rt") as fp:
            versions_list = json.loads(fp.read())
            self.signatures_files = versions_list["signatures_files"]
            versions_list.pop("signatures_files")
            self.versions_list = VersionListSchema().load(versions_list).data

    def identify_version(self, target):
        files = list(self.fetch_files(target))
        for version_definition in self.versions_list.versions:
            if self._files_match_version(files, version_definition):
                return version_definition.version

    def fetch_files(self, target):
        for file in self.signatures_files:
            url = target + file
            self.hammertime.request(url)
        for entry in self.hammertime.successful_requests():
            yield entry.response

    def get_file_hash(self, file, algo):
        hasher = hashlib.new(algo)
        hasher.update(file.data)
        return hasher.hexdigest()

    def _files_match_version(self, files, version_definition):
        for signature in version_definition.signatures:
            for file in files:
                if signature.path == file.name:
                    if not self._file_match_signature(file, signature):
                        return False
        return True

    def _file_match_signature(self, file, signature):
        file_hash = self.get_file_hash(file, signature.algo)
        return file_hash == signature.hash

    class File:

        def __init__(self, name, data):
            self.name = name
            self.data = data
