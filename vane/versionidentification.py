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
from collections import Counter
import re
from packaging import version


version_pattern = re.compile("(?<=ver=)\d+\.\d+(?:\.\d+)?")
generator_version_pattern = re.compile('(?<=<meta name="generator" content="WordPress )\d+\.\d+(?:\.\d+)?')
wp_links_opml_exposed_version_pattern = re.compile('(?<=<!-- generator="WordPress/)\d+\.\d+(?:\.\d+)?')


class VersionIdentification:

    def __init__(self):
        self.fetched_files_confidence = 100

    def identify_version(self, fetched_files, version_identification_file_list, files_exposing_version=None):
        possible_versions = self._get_possible_versions(fetched_files, version_identification_file_list)

        if files_exposing_version:
            versions = self.find_versions_in_source_files(files_exposing_version)
            return self.get_most_reliable_version(fetched_files_versions=possible_versions,
                                                  source_files_versions=versions)
        else:
            return self.get_most_reliable_version(fetched_files_versions=possible_versions)

    def set_confidence_level_of_fetched_files(self, confidence_level):
        self.fetched_files_confidence = confidence_level

    def get_most_reliable_version(self, *, fetched_files_versions=None, source_files_versions=None):
        if fetched_files_versions and source_files_versions:
            common_versions = fetched_files_versions & source_files_versions
            if len(common_versions) > 0:
                return self._get_lowest_version(common_versions)
            else:
                if self.fetched_files_confidence == 100:
                    return self._get_lowest_version(fetched_files_versions)
                else:
                    versions = self._get_versions_with_same_minor(source_files_versions, fetched_files_versions)
                    if len(versions) > 0:
                        return self._get_lowest_version(versions)
                    else:
                        versions = self._get_versions_with_same_major(source_files_versions, fetched_files_versions)
                        if len(versions) > 0:
                            return self._get_lowest_version(versions)
                        else:
                            return None
        elif fetched_files_versions:
            return self._get_lowest_version(fetched_files_versions)
        elif source_files_versions:
            return self._get_lowest_version(source_files_versions)

    def _get_lowest_version(self, versions):
        sorted_versions = VersionCompare.sorted(versions)
        return sorted_versions[0]

    def _get_possible_versions(self, fetched_files, file_list):
        possible_versions = Counter()
        for file in fetched_files:
            versions = self._get_possible_versions_for_fetched_file(file, file_list)
            if versions is not None:
                possible_versions.update(versions)
        file_count_per_version = possible_versions.most_common()
        if len(file_count_per_version) == 0:
            return {}
        _, highest_file_count = file_count_per_version[0]
        versions = {version for version, file_count in file_count_per_version if file_count == highest_file_count}
        return versions

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
        wp_links_opml_version = wp_links_opml_exposed_version_pattern.search(file_response.content)
        if wp_links_opml_version is not None:
            return {wp_links_opml_version.group()}
        return set(version_pattern.findall(file_response.content))

    def _get_versions_with_same_major(self, version_set, other_version_set):
        versions = set()
        for version in version_set:
            for _version in other_version_set:
                if self._is_same_major(version, _version):
                    versions.add(version)
        return versions

    def _get_versions_with_same_minor(self, version_set, other_version_set):
        versions = set()
        for version in version_set:
            for _version in other_version_set:
                if self._is_same_minor(version, _version):
                    versions.add(version)
        return versions

    def _is_same_major(self, version0, version1):
        return version.parse(version0)._version.release[0] == version.parse(version1)._version.release[0]

    def _is_same_minor(self, version0, version1):
        if self._is_same_major(version0, version1):
            return version.parse(version0)._version.release[1] == version.parse(version1)._version.release[1]
