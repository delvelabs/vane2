from unittest import TestCase
from unittest.mock import MagicMock, call
from vane.versionidentification import VersionIdentification
import hashlib
from openwebvulndb.wordpress.vane2models import Signature, File, FilesList
from openwebvulndb.wordpress.vane2schemas import FilesListSchema
from os.path import join, dirname


class TestVersionIdentification(TestCase):

    def setUp(self):
        self.hammertime = MagicMock()
        self.version_identification = VersionIdentification(self.hammertime)
        self.version_identification.files_list = MagicMock()
        self.readme_file = VersionIdentification.FetchedFile("readme.html", b"This is the readme file.")
        self.style_css_file = VersionIdentification.FetchedFile("style.css", b"This is the style file.")

    def test_fetch_files_make_request_to_hammertime(self):
        self.version_identification.get_files_to_fetch = MagicMock()
        self.version_identification.get_files_to_fetch.return_value = ["readme.html", "style.css", "wp-include/file.js"]
        target = "http://www.target.url/"

        for file in self.version_identification.fetch_files(target):
            pass  # Iterate over fetch files to make the request calls.

        self.hammertime.request.assert_has_calls([call(target + "readme.html"), call(target + "style.css"),
                                                  call(target + "wp-include/file.js")])
        self.hammertime.successful_requests.assert_any_call()

    def test_fetch_files_return_fetched_files(self):
        self.version_identification.get_files_to_fetch = MagicMock()
        self.version_identification.get_files_to_fetch.return_value = ["readme.html", "style.css"]
        target = "http://www.target.url/"

        readme_http_entry = MagicMock()
        readme_http_entry.response.raw = b"readme file"
        readme_http_entry.request.url = target + "readme.html"

        style_http_entry = MagicMock()
        style_http_entry.response.raw = b"style css file"
        style_http_entry.request.url = target + "style.css"

        self.hammertime.successful_requests.return_value = [style_http_entry, readme_http_entry]

        fetched_files = list(self.version_identification.fetch_files(target))

        fetched_style_file = fetched_files[0]
        fetched_readme_file = fetched_files[1]
        self.assertEqual(fetched_style_file.name, "style.css")
        self.assertEqual(fetched_style_file.data, b"style css file")
        self.assertEqual(fetched_readme_file.name, "readme.html")
        self.assertEqual(fetched_readme_file.data, b"readme file")

    def test_get_file_hash_return_valid_hash(self):
        expected_file_hash_sha256 = hashlib.sha256(self.readme_file.data).hexdigest()
        expected_file_hash_md5 = hashlib.md5(self.readme_file.data).hexdigest()

        file_hash_sha256 = self.version_identification.get_file_hash(self.readme_file, "sha256")
        file_hash_md5 = self.version_identification.get_file_hash(self.readme_file, "md5")

        self.assertEqual(file_hash_sha256, expected_file_hash_sha256)
        self.assertEqual(file_hash_md5, expected_file_hash_md5)

    def test_get_signature_that_match_file(self):
        fetched_file = VersionIdentification.FetchedFile("readme.html", b"ReadMe file version 2.0")
        readme_1_signature = Signature(hash=self.hash_data(b"ReadMe file version 1.0"), versions=["1.0"])
        readme_2_signature = Signature(hash=self.hash_data(b"ReadMe file version 2.0"), versions=["2.0"])
        file_signature = File(path="readme.html", signatures=[readme_1_signature, readme_2_signature])
        files_list = FilesList(key="wordpress", producer="", files=[file_signature])
        self.version_identification.files_list = files_list

        signature = self.version_identification._get_signature_that_match_fetched_file(fetched_file)

        self.assertEqual(signature, readme_2_signature)

    def test_identify_version(self):
        style_css_signature = Signature(hash=self.hash_data(self.style_css_file.data), versions=["1.0", "2.0"])
        style_css_file = File(path="style.css", signatures=[style_css_signature])

        readme_1_signature = Signature(hash=self.hash_data(b"ReadMe file for 1.0 version."), versions=["1.0"])
        readme_2_signature = Signature(hash=self.hash_data(b"ReadMe file for 2.0 version."), versions=["2.0"])
        readme_file = File(path="readme.html", signatures=[readme_1_signature, readme_2_signature])

        files_list = FilesList(producer="unittest", key="wordpress", files=[readme_file, style_css_file])
        version_identification = VersionIdentification(None)
        version_identification.files_list = files_list

        version_identification.fetch_files = MagicMock()
        fetched_readme = VersionIdentification.FetchedFile("readme.html", b"ReadMe file for 2.0 version.")
        version_identification.fetch_files.return_value = [fetched_readme, self.style_css_file]

        version = version_identification.identify_version("target")

        self.assertEqual(version, "2.0")

    def test_identify_version_find_closest_match_when_one_file_is_missing(self):
        style_css_signature = Signature(hash=self.hash_data(self.style_css_file.data),
                                        versions=["1.0", "2.0"])
        style_css_file = File(path="style.css", signatures=[style_css_signature])

        readme_1_signature = Signature(hash=self.hash_data(b"ReadMe file for 1.0 version."), versions=["1.0"])
        readme_2_signature = Signature(hash=self.hash_data(b"ReadMe file for 2.0 version."), versions=["2.0"])
        readme_file = File(path="readme.html", signatures=[readme_1_signature, readme_2_signature])

        login_js_signature_1 = Signature(hash=self.hash_data(b"login.js file v1."), versions=["1.0"])
        login_js_signature_2 = Signature(hash=self.hash_data(b"login.js file v2."), versions=["2.0"])
        login_js_file = File(path="login.js", signatures=[login_js_signature_1, login_js_signature_2])

        files_list = FilesList(producer="unittest", key="wordpress", files=[readme_file, style_css_file, login_js_file])
        version_identification = VersionIdentification(None)
        version_identification.files_list = files_list

        version_identification.fetch_files = MagicMock()
        fetched_login = VersionIdentification.FetchedFile("login.js", b"login.js file v1.")
        version_identification.fetch_files.return_value = [fetched_login, self.style_css_file]

        version = version_identification.identify_version("target")

        self.assertEqual(version, "1.0")

    def test_identify_version_give_major_version_if_cant_identify_precise_version(self):
        style_css_signature_1 = Signature(hash=self.hash_data(b"style css versions 1.x"), versions=["1.0", "1.1"])
        style_css_signature_2 = Signature(hash=self.hash_data(b"style css version 2.x"), versions=["2.0", "2.1"])
        style_css_file = File(path="style.css", signatures=[style_css_signature_1, style_css_signature_2])

        files_list = FilesList(producer="unittest", key="wordpress", files=[style_css_file])
        version_identification = VersionIdentification(None)
        version_identification.files_list = files_list

        version_identification.fetch_files = MagicMock()
        fetched_style_file = VersionIdentification.FetchedFile("style.css", b"style css version 2.x")
        version_identification.fetch_files.return_value = [fetched_style_file]
        version_identification.major_version_pattern = "\d+"

        version = version_identification.identify_version("target")

        self.assertEqual(version, "2.x")

    def test_identify_version_return_none_if_no_major_version_can_be_identify(self):
        style_css_signature = Signature(hash=self.hash_data(b"style css version 1.x"), versions=["1.0", "1.1"])
        style_css_file = File(path="style.css", signatures=[style_css_signature])

        files_list = FilesList(producer="unittest", key="wordpress", files=[style_css_file])
        version_identification = VersionIdentification(None)
        version_identification.files_list = files_list

        version_identification.fetch_files = MagicMock()
        fetched_style_file = VersionIdentification.FetchedFile("style.css", b"style css version 1.x")
        version_identification.fetch_files.return_value = [fetched_style_file]
        version_identification.major_version_pattern = "\d+\.\d+"

        version = version_identification.identify_version("target")

        self.assertIsNone(version)

    def test_load_versions_signatures(self):
        filename = join(dirname(__file__), "samples/vane2_versions.json")

        self.version_identification.load_files_signatures(filename)

        files_list = FilesListSchema().dump(self.version_identification.files_list).data
        files_list = self.wrap_lists_in_unordered_lists(files_list)

        self.assertEqual(files_list, {"key": "wordpress", "producer": "unittest", "files":
            [{"path": "readme.html", "signatures": [{"hash": "1234", "algo": "SHA256", "versions": ["1.0"]},
                                                    {"hash": "2345", "algo": "SHA256", "versions": ["2.0"]}]},
             {"path": "file.js", "signatures": [{"hash": "4321", "algo": "SHA256", "versions": ["1.0", "2.0"]}]}]})

    def test_get_common_major_version(self):
        versions1 = ["1.0", "1.1", "1.2", "1.6"]
        versions2_5 = ["2.5.1", "2.5.3", "2.5.6"]
        versions_mixed = ["1.9.2", "4.5.1", "6.7.2"]

        major_version1 = self.version_identification._get_common_major_version(versions1, "\d+")
        major_version2_5 = self.version_identification._get_common_major_version(versions2_5, "\d+\.\d+")
        no_major_version = self.version_identification._get_common_major_version(versions_mixed, "\d+\.\d+")

        self.assertEqual(major_version1, "1.x")
        self.assertEqual(major_version2_5, "2.5.x")
        self.assertIsNone(no_major_version)


    # Fixtures for the tests

    def hash_data(self, data, algo="SHA256"):
        hasher = hashlib.new(algo)
        hasher.update(data)
        return hasher.hexdigest()

    def wrap_lists_in_unordered_lists(self, iterable):
        """Iterate over the contents of a iterable and wrap all lists elements into UnorderedList"""
        if type(iterable) == dict:
            for key, value in iterable.items():
                iterable[key] = self.wrap_lists_in_unordered_lists(value)
            return iterable
        elif type(iterable) == list:
            li = [self.wrap_lists_in_unordered_lists(element) for element in iterable]
            return self.UnorderedList(li)
        else:
            return iterable

    class UnorderedList:
        """Wrapper for a list, used for equality assertion so the element order doesn't matter."""

        def __init__(self, list):
            self.list = list

        def __eq__(self, other):
            if type(other) == list:
                for element in self.list:
                    if element in other:
                        return True
                    else:
                        return False
            return False
