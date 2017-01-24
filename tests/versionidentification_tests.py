from unittest import TestCase
from unittest.mock import MagicMock, call
from vane.versionidentification import VersionIdentification
import hashlib
from openwebvulndb.wordpress.vane2models import Signature, File, FilesList
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
            pass

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

    def test_get_versions_that_match_file_hash(self):
        file_signature1 = Signature(hash="1234", versions=["1.0"])
        file_signature2 = Signature(hash="2345", versions=["1.1", "1.2"])
        signatures = [file_signature1, file_signature2]

        versions1 = self.version_identification._get_versions_that_match_file_hash("1234", signatures)
        versions2 = self.version_identification._get_versions_that_match_file_hash("2345", signatures)

        self.assertEqual(versions1, ["1.0"])
        self.assertIn("1.1", versions2)
        self.assertIn("1.2", versions2)

    def test_get_signature_that_match_file(self):
        fetched_file = VersionIdentification.FetchedFile("readme.html", b"ReadMe file version 2.0")
        readme_1_signature = Signature(hash=hashlib.sha256(b"ReadMe file version 1.0").hexdigest(), versions=["1.0"])
        readme_2_signature = Signature(hash=hashlib.sha256(b"ReadMe file version 2.0").hexdigest(), versions=["2.0"])
        file_signature = File(path="readme.html", signatures=[readme_1_signature, readme_2_signature])
        files_list = FilesList(key="wordpress", producer="", files=[file_signature])
        self.version_identification.files_list = files_list

        signature = self.version_identification._get_signature_that_match_fetched_file(fetched_file)

        self.assertEqual(signature, readme_2_signature)

    def test_identify_version(self):
        style_css_signature = Signature(hash=hashlib.sha256(self.style_css_file.data).hexdigest(), versions=["1.0", "2.0"])
        style_css_file = File(path="style.css", signatures=[style_css_signature])

        readme_1_signature = Signature(hash=hashlib.sha256(b"ReadMe file for 1.0 version.").hexdigest(), versions=["1.0"])
        readme_2_signature = Signature(hash=hashlib.sha256(b"ReadMe file for 2.0 version.").hexdigest(), versions=["2.0"])
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
        style_css_signature = Signature(hash=hashlib.sha256(self.style_css_file.data).hexdigest(),
                                        versions=["1.0", "2.0"])
        style_css_file = File(path="style.css", signatures=[style_css_signature])

        readme_1_signature = Signature(hash=hashlib.sha256(b"ReadMe file for 1.0 version.").hexdigest(),
                                       versions=["1.0"])
        readme_2_signature = Signature(hash=hashlib.sha256(b"ReadMe file for 2.0 version.").hexdigest(),
                                       versions=["2.0"])
        readme_file = File(path="readme.html", signatures=[readme_1_signature, readme_2_signature])

        login_js_signature_1 = Signature(hash=hashlib.sha256(b"login.js file v1.").hexdigest(), versions=["1.0"])
        login_js_signature_2 = Signature(hash=hashlib.sha256(b"login.js file v2.").hexdigest(), versions=["2.0"])
        login_js_file = File(path="login.js", signatures=[login_js_signature_1, login_js_signature_2])

        files_list = FilesList(producer="unittest", key="wordpress", files=[readme_file, style_css_file, login_js_file])
        version_identification = VersionIdentification(None)
        version_identification.files_list = files_list

        version_identification.fetch_files = MagicMock()
        fetched_login = VersionIdentification.FetchedFile("login.js", b"login.js file v1.")
        version_identification.fetch_files.return_value = [fetched_login, self.style_css_file]

        version = version_identification.identify_version("target")

        self.assertEqual(version, "1.0")

    def test_load_versions_signatures(self):
        filename = join(dirname(__file__), "samples/vane2_versions.json")

        self.version_identification.load_files_signatures(filename)

        self.assertEqual(self.version_identification.files_list.key, "wordpress")
        self.assertEqual(self.version_identification.files_list.producer, "unittest")
        for file in self.version_identification.files_list.files:
            if file.path == "readme.html":
                for signature in file.signatures:
                    self.assertTrue(signature.hash == "1234" and signature.versions == ["1.0"] or
                                    signature.hash == "2345" and signature.versions == ["2.0"])
            else:
                self.assertEqual(file.path, "file.js")
                self.assertEqual(file.signatures[0].hash, "4321")
                self.assertIn("1.0", file.signatures[0].versions)
                self.assertIn("2.0", file.signatures[0].versions)
