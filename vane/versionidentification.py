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


version_pattern = re.compile("(?<=ver=)\d+\.\d+(?:\.\d+)?")
generator_version_pattern = re.compile('(?<=<meta name="generator" content="WordPress )\d+\.\d+(?:\.\d+)?')


class VersionIdentification:

    def identify_version(self, fetched_files, version_identification_file_list, files_exposing_version=None):
        possible_versions = self._get_possible_versions(fetched_files, version_identification_file_list)

        if files_exposing_version and len(possible_versions) > 1:
            versions = self.find_versions_in_source_files(files_exposing_version)
            if len(versions & possible_versions) > 0:
                possible_versions &= versions

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
                print("With {}, possible versions are now: {}".format(file, possible_versions))
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

    def find_versions_in_source_files(self, file_response_list):
        versions_from_files = set()
        for response in file_response_list:
            versions_from_files |= self._find_versions_in_file(response)
        return versions_from_files

    def _find_versions_in_file(self, file_response):
        generator_version = generator_version_pattern.search(file_response.content)
        if generator_version is not None:
            return {generator_version.group()}
        return set(version_pattern.findall(file_response.content))
