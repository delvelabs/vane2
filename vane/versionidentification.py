import hashlib


# TODO add a script to check if two version signature are equal, and log a warning if it happens (put this script in the
# TODO openwebvulndb exporter, when a new versions file is generated?)
class VersionIdentification:

    # TODO remove plugin and theme files from files used to identify version.
    def __init__(self, versions_list, hammertime):
        # version list comes from openwebvulndb
        self.versions_list = versions_list
        self.hammertime = hammertime

    def identify_version(self, target):
        #fetch_files
        #for VersionDefinition in version_list:
        #   hash_files(files, version_definition.signatures)
        #   if all hashed_file match:
        #       return version
        pass

    def fetch_files(self, target):
        for file in self.get_files_to_fetch():
            url = target + file
            self.hammertime.request(url)
        for entry in self.hammertime.successful_requests():
            yield entry.response

    def hash_files(self, files, signatures_list):
        # if the same files are reused, the hash and algo are kept from one version check to another, fix this.
        for signature in signatures_list:
            for file in files:
                if file.name == signature.path:
                    file.algo = signature.algo
                    file.hash = self.get_file_hash(file, file.algo)

    def get_file_hash(self, file, algo):
        hasher = hashlib.new(algo)
        hasher.update(file.data)
        return hasher.hexdigest()

    class File:

        def __init__(self, name, data):
            self.name = name
            self.data = data
            self.hash = None
            self.algo = None
