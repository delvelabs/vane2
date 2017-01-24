import hashlib
import json
from openwebvulndb.wordpress.vane2schemas import FilesListSchema


class VersionIdentification:

    def __init__(self, hammertime):
        # version list comes from openwebvulndb
        self.files_list = None
        self.hammertime = hammertime

    def load_files_signatures(self, filename):
        with open(filename, "rt") as fp:
            schema = FilesListSchema()
            self.files_list = schema.load(json.load(fp)).data

    def identify_version(self, target):
        possible_versions = set()
        for fetched_file in self.fetch_files(target):
            signature = self._get_signature_that_match_fetched_file(fetched_file)
            if len(possible_versions) > 0:
                possible_versions &= set(signature.versions)
            else:
                possible_versions = set(signature.versions)
        if len(possible_versions) > 1:
            return [version for version in possible_versions][0]  # TODO return major version if only one major version, else fail?
        elif len(possible_versions) == 1:
            return [version for version in possible_versions][0]

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

    def _get_versions_that_match_file_hash(self, file_hash, signatures):
        for signature in signatures:
            if signature.hash == file_hash:
                return signature.versions

    def _get_file_from_files_list(self, filename):
        for file in self.files_list.files:
            if file.path == filename:
                return file

    class FetchedFile:

        def __init__(self, name, data):
            self.name = name
            self.data = data
