import hashlib
import json
from openwebvulndb.common.schemas import FileListSchema
import packaging.version


class VersionIdentification:

    def __init__(self, hammertime):
        self.file_list = None
        self.hammertime = hammertime

    def load_files_signatures(self, filename):
        with open(filename, "rt") as fp:
            schema = FileListSchema()
            data, errors = schema.load(json.load(fp))
            if errors:
                raise Exception(errors)
            self.file_list = data

    async def identify_version(self, target):
        possible_versions = set()
        fetched_files = await self.fetch_files(target)
        files_signatures = self._get_fetched_files_signatures(fetched_files)
        for signature in files_signatures:
            if len(possible_versions) > 0:
                possible_versions &= set(signature.versions)
            else:
                possible_versions = set(signature.versions)

        await self.hammertime.close()

        version = None
        if len(possible_versions) > 1:
            version = self._get_common_minor_version(possible_versions)
        elif len(possible_versions) == 1:
            version = possible_versions.pop()
        return version or "could not identify %s wordpress version" % target

    def _get_common_minor_version(self, versions):
        common_versions = set()
        for version in versions:
            _version = packaging.version.parse(version)
            major_version = _version._version.release[0]
            minor_version = _version._version.release[1]
            common_versions.add("{0}.{1}".format(major_version, minor_version))
        if len(common_versions) > 1:
            return None
        return common_versions.pop() + ".x"

    async def fetch_files(self, target):
        for file_path in self.get_files_to_fetch():
            if not target.endswith('/'):
                target += '/'
            url = target + file_path
            self.hammertime.request(url)
        fetched_files = []
        async for entry in self.hammertime.successful_requests():
            file_name = entry.request.url[len(target):]
            fetched_file = self.FetchedFile(file_name, entry.response.raw)
            fetched_files.append(fetched_file)
        return fetched_files

    def get_files_to_fetch(self):
        for file in self.file_list.files:
            yield file.path

    def get_file_hash(self, file, algo):
        hasher = hashlib.new(algo)
        hasher.update(file.data)
        return hasher.hexdigest()

    def _get_fetched_files_signatures(self, fetched_files):
        signatures = []
        for file in fetched_files:
            signature = self._get_file_signature_matching_fetched_file(file)
            if signature is not None:
                signatures.append(signature)
        return signatures

    def _get_file_signature_matching_fetched_file(self, fetched_file):
        file = self._get_file_from_file_list(fetched_file.name)
        if file is not None:
            signatures = file.signatures
            for signature in signatures:
                file_hash = self.get_file_hash(fetched_file, signature.algo)
                if file_hash == signature.hash:
                    return signature
        return None

    def _get_file_from_file_list(self, filename):
        for file in self.file_list.files:
            if file.path == filename:
                return file
        return None

    class FetchedFile:

        def __init__(self, name, data):
            self.name = name
            self.data = data
