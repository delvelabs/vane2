import hashlib
import json
from openwebvulndb.wordpress.vane2schemas import FilesListSchema
import re


class VersionIdentification:

    def __init__(self, hammertime):
        self.files_list = None
        self.hammertime = hammertime
        self.major_version_pattern = "\d+\.\d+"

    def load_files_signatures(self, filename):
        with open(filename, "rt") as fp:
            schema = FilesListSchema()
            self.files_list = schema.load(json.load(fp)).data

    def identify_version(self, target):
        possible_versions = set()
        for fetched_file in self.fetch_files(target):
            signature = self._get_signature_that_match_fetched_file(fetched_file)
            if signature is not None:
                if len(possible_versions) > 0:
                    possible_versions &= set(signature.versions)
                else:
                    possible_versions = set(signature.versions)
        if len(possible_versions) > 1:
            return self._get_common_major_version(possible_versions, self.major_version_pattern)
        return possible_versions.pop()

    def _get_common_major_version(self, versions, major_version_pattern):
        major_versions = set()
        for version in versions:
            major_version = re.match(major_version_pattern, version).group()
            major_versions.add(major_version)
        if len(major_versions) > 1:
            return None
        return major_versions.pop() + ".x"

    def fetch_files(self, target):
        for file_path in self.get_files_to_fetch():
            url = target + file_path
            self.hammertime.request(url)
        for entry in self.hammertime.successful_requests():
            file_name = entry.request.url[len(target):]
            fetched_file = self.FetchedFile(file_name, entry.response.raw)
            yield fetched_file

    def get_files_to_fetch(self):
        for file in self.files_list.files:
            yield file.path

    def get_file_hash(self, file, algo):
        hasher = hashlib.new(algo)
        hasher.update(file.data)
        return hasher.hexdigest()

    def _get_signature_that_match_fetched_file(self, fetched_file):
        signatures = self._get_file_from_files_list(fetched_file.name).signatures
        for signature in signatures:
            file_hash = self.get_file_hash(fetched_file, signature.algo)
            if file_hash == signature.hash:
                return signature

    def _get_file_from_files_list(self, filename):
        for file in self.files_list.files:
            if file.path == filename:
                return file

    class FetchedFile:

        def __init__(self, name, data):
            self.name = name
            self.data = data
