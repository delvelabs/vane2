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

from unittest import TestCase
from vane.versionidentification import VersionIdentification
from openwebvulndb.common.models import FileSignature, File, FileList
from vane.filefetcher import FetchedFile


class TestVersionIdentification(TestCase):

    def setUp(self):
        self.version_identification = VersionIdentification()

        self.readme_fetched_file = FetchedFile(path="readme.html", hash="12345")
        self.style_css_fetched_file = FetchedFile(path="style.css", hash="09876")

        self.readme_1_signature = FileSignature(hash=self.readme_fetched_file.hash, versions=["1.0"])
        self.readme_2_signature = FileSignature(hash="23456", versions=["2.0"])
        self.readme_file = File(path="readme.html", signatures=[self.readme_1_signature, self.readme_2_signature])

        self.style_css_signature = FileSignature(hash=self.style_css_fetched_file.hash, versions=["1.0", "2.0"])
        self.style_css_file = File(path="style.css", signatures=[self.style_css_signature])

        self.file_list = FileList(key="", producer="", files=[self.readme_file, self.style_css_file])

    def test_get_possible_versions_for_fetched_file(self):
        file_list = FileList(key="wordpress", producer="", files=[self.readme_file])

        versions = self.version_identification._get_possible_versions_for_fetched_file(self.readme_fetched_file,
                                                                                       file_list)

        self.assertEqual(versions, self.readme_1_signature.versions)

    def test_identify_version(self):
        file_list = FileList(producer="unittest", key="wordpress", files=[self.readme_file, self.style_css_file])
        fetched_files = [self.readme_fetched_file, self.style_css_fetched_file]

        version = self.version_identification.identify_version(fetched_files, file_list)

        self.assertEqual(version, "1.0")

    def test_identify_version_find_closest_match_when_one_file_is_missing(self):
        login_js_signature_1 = FileSignature(hash="11111", versions=["1.0"])
        login_js_signature_2 = FileSignature(hash="22222", versions=["2.0"])
        login_js_file = File(path="login.js", signatures=[login_js_signature_1, login_js_signature_2])

        file_list = FileList(producer="unittest", key="wordpress", files=[self.readme_file, self.style_css_file,
                                                                          login_js_file])
        fetched_login = FetchedFile(path="login.js", hash="11111")
        fetched_files = [fetched_login, self.style_css_fetched_file]

        version = self.version_identification.identify_version(fetched_files, file_list)

        self.assertEqual(version, "1.0")

    def test_identify_version_return_lowest_version_if_cant_identify_precise_version(self):
        style_css_signature = FileSignature(hash=self.style_css_fetched_file.hash, versions=["2.0.0", "2.0.1"])
        style_css_file = File(path="style.css", signatures=[style_css_signature])

        file_list = FileList(producer="unittest", key="wordpress", files=[style_css_file])

        version = self.version_identification.identify_version([self.style_css_fetched_file], file_list)

        self.assertEqual(version, "2.0.0")

    def test_identify_version_return_none_if_no_version_found(self):
        file_list = FileList(producer="unittest", key="wordpress", files=[self.style_css_file])

        version = self.version_identification.identify_version([self.readme_fetched_file], file_list)

        self.assertIsNone(version)

    def test_get_lowest_version(self):
        versions = ["1.3.0", "1.3.1", "4.7.0", "2.7.6", "1.0.12"]

        version = self.version_identification._get_lowest_version(versions)

        self.assertEqual(version, "1.0.12")
