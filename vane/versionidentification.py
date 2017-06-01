# Vane 2.0: A web application vulnerability assessment tool.
# Copyright (C) 2017-  Delve Labs inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

from openwebvulndb.common.version import VersionCompare

import re


class VersionIdentification:

    def identify_version(self, fetched_files, version_identification_file_list, source_files=None):
        possible_versions = self._get_possible_versions(fetched_files, version_identification_file_list)

        if source_files and len(possible_versions) > 1:
            possible_versions = self.find_version_from_source_files(source_files, possible_versions)

        if len(possible_versions) > 1:
            return self._get_lowest_version(possible_versions)
        elif len(possible_versions) == 1:
            return possible_versions.pop()
        return None

    def _get_lowest_version(self, versions):
        sorted_versions = VersionCompare.sorted(versions)
        return sorted_versions[0]

    def _get_possible_versions(self, fetched_files, file_list):
        possible_versions = set()
        for file in fetched_files:
            versions = self._get_possible_versions_for_fetched_file(file, file_list)
            if versions is not None:
                if len(possible_versions) > 0:
                    possible_versions &= set(versions)
                else:
                    possible_versions = set(versions)
        return possible_versions

    def _get_possible_versions_for_fetched_file(self, fetched_file, file_list):
        file = self._get_file_from_file_list(fetched_file.path, file_list)
        if file is not None:
            signatures = file.signatures
            for signature in signatures:
                if fetched_file.hash == signature.hash:
                    return signature.versions
        return None

    def _get_file_from_file_list(self, file_path, file_list):
        for file in file_list.files:
            if file.path == file_path:
                return file
        return None

    def find_version_from_source_files(self, files_hammertime_response, possible_versions):
        versions_from_files = set()
        for response in files_hammertime_response:
            versions_from_files |= self.find_possible_versions_from_source_file(response)
        return versions_from_files & possible_versions

    def find_possible_versions_from_source_file(self, file_hammertime_response):
        version_string_list = re.findall("ver=\d+\.\d+\.\d+", file_hammertime_response.content)
        version_set = set(re.sub("ver=", "", version_string) for version_string in version_string_list)
        return version_set
