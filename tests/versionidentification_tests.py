from unittest import TestCase
from unittest.mock import MagicMock, call
from vane.versionidentification import VersionIdentification
import hashlib
from openwebvulndb.common.models import FileSignature, File, FileList
from openwebvulndb.common.schemas import FileListSchema
from os.path import join, dirname
from vane.hammertime.tests.fixtures import async_test
from fixtures import FakeAsyncIterator, hash_data, wrap_lists_in_unordered_lists


class TestVersionIdentification(TestCase):

    def setUp(self):
        self.hammertime = MagicMock()

        async def hammertime_close():
            pass

        self.hammertime.close = hammertime_close
        self.version_identification = VersionIdentification(self.hammertime)
        self.version_identification.file_list = MagicMock()
        self.version_identification.get_files_to_fetch = MagicMock()

        self.readme_fetched_file = VersionIdentification.FetchedFile("readme.html", b"This is the readme file.")
        self.style_css_fetched_file = VersionIdentification.FetchedFile("style.css", b"This is the style file.")

        self.readme_1_signature = FileSignature(hash=hash_data(self.readme_fetched_file.data), versions=["1.0"])
        self.readme_2_signature = FileSignature(hash=hash_data(b"ReadMe file version 2.0"), versions=["2.0"])
        self.readme_file = File(path="readme.html", signatures=[self.readme_1_signature, self.readme_2_signature])

        self.style_css_signature = FileSignature(hash=hash_data(self.style_css_fetched_file.data),
                                                 versions=["1.0", "2.0"])
        self.style_css_file = File(path="style.css", signatures=[self.style_css_signature])

    @async_test()
    async def test_fetch_files_make_request_to_hammertime(self):
        self.version_identification.get_files_to_fetch.return_value = ["readme.html", "style.css", "wp-include/file.js"]
        target = "http://www.target.url/"
        self.hammertime.successful_requests.return_value = FakeAsyncIterator([])

        await self.version_identification.fetch_files(target)

        self.hammertime.request.assert_has_calls([call(target + "readme.html"), call(target + "style.css"),
                                                  call(target + "wp-include/file.js")])
        self.hammertime.successful_requests.assert_any_call()

    @async_test()
    async def test_fetch_files_return_fetched_files(self):
        self.version_identification.get_files_to_fetch.return_value = ["readme.html", "style.css"]
        target = "http://www.target.url/"

        readme_http_entry = MagicMock()
        readme_http_entry.response.raw = b"readme file"
        readme_http_entry.request.url = target + "readme.html"

        style_http_entry = MagicMock()
        style_http_entry.response.raw = b"style css file"
        style_http_entry.request.url = target + "style.css"

        self.hammertime.successful_requests.return_value = FakeAsyncIterator([style_http_entry, readme_http_entry])

        fetched_files = await self.version_identification.fetch_files(target)

        fetched_style_file = fetched_files[0]
        fetched_readme_file = fetched_files[1]
        self.assertEqual(fetched_style_file.name, "style.css")
        self.assertEqual(fetched_style_file.data, b"style css file")
        self.assertEqual(fetched_readme_file.name, "readme.html")
        self.assertEqual(fetched_readme_file.data, b"readme file")

    @async_test()
    async def test_fetch_files_join_target_url_and_file_path(self):
        url_ending_with_slash = "https://preview.wardenscanner.com/"
        url_without_ending_slash = "https://preview.wardenscanner.com"

        self.version_identification.get_files_to_fetch.return_value = ["readme.html", "wp-admin/list-manipulation.js"]
        self.hammertime.successful_requests.return_value = FakeAsyncIterator([])

        await self.version_identification.fetch_files(url_ending_with_slash)
        await self.version_identification.fetch_files(url_without_ending_slash)

        self.hammertime.request.assert_has_calls([call("https://preview.wardenscanner.com/readme.html"),
                                                 call("https://preview.wardenscanner.com/wp-admin/list-manipulation.js"),
                                                 call("https://preview.wardenscanner.com/readme.html"),
                                                 call("https://preview.wardenscanner.com/wp-admin/list-manipulation.js")])

    def test_get_file_hash_return_valid_hash(self):
        expected_file_hash_sha256 = hashlib.sha256(self.readme_fetched_file.data).hexdigest()
        expected_file_hash_md5 = hashlib.md5(self.readme_fetched_file.data).hexdigest()

        file_hash_sha256 = self.version_identification.get_file_hash(self.readme_fetched_file, "sha256")
        file_hash_md5 = self.version_identification.get_file_hash(self.readme_fetched_file, "md5")

        self.assertEqual(file_hash_sha256, expected_file_hash_sha256)
        self.assertEqual(file_hash_md5, expected_file_hash_md5)

    def test_get_file_signature_matching_fetched_file(self):
        file_list = FileList(key="wordpress", producer="", files=[self.readme_file])
        self.version_identification.file_list = file_list

        signature = self.version_identification._get_file_signature_matching_fetched_file(self.readme_fetched_file)

        self.assertEqual(signature, self.readme_1_signature)

    @async_test()
    async def test_identify_version(self):
        file_list = FileList(producer="unittest", key="wordpress", files=[self.readme_file, self.style_css_file])
        self.version_identification.file_list = file_list

        async def fetch_files(*args):
            return [self.readme_fetched_file, self.style_css_fetched_file]

        self.version_identification.fetch_files = fetch_files

        version = await self.version_identification.identify_version("target")

        self.assertEqual(version, "1.0")

    @async_test()
    async def test_identify_version_find_closest_match_when_one_file_is_missing(self):
        login_js_signature_1 = FileSignature(hash=hash_data(b"login.js file v1."), versions=["1.0"])
        login_js_signature_2 = FileSignature(hash=hash_data(b"login.js file v2."), versions=["2.0"])
        login_js_file = File(path="login.js", signatures=[login_js_signature_1, login_js_signature_2])

        file_list = FileList(producer="unittest", key="wordpress", files=[self.readme_file, self.style_css_file,
                                                                          login_js_file])

        self.version_identification.file_list = file_list
        fetched_login = VersionIdentification.FetchedFile("login.js", b"login.js file v1.")

        async def fetch_files(*args):
            return [fetched_login, self.style_css_fetched_file]
        self.version_identification.fetch_files = fetch_files

        version = await self.version_identification.identify_version("target")

        self.assertEqual(version, "1.0")

    @async_test()
    async def test_identify_version_give_major_version_if_cant_identify_precise_version(self):
        style_css_signature_1 = FileSignature(hash=hash_data(b"style css versions 1.x"), versions=["1.0.1", "1.0.2"])
        style_css_signature_2 = FileSignature(hash=hash_data(self.style_css_fetched_file.data), versions=["2.0", "2.0.1"])
        style_css_file = File(path="style.css", signatures=[style_css_signature_1, style_css_signature_2])

        file_list = FileList(producer="unittest", key="wordpress", files=[style_css_file])
        version_identification = VersionIdentification(self.hammertime)
        version_identification.file_list = file_list

        async def fetch_files(*args):
            return [self.style_css_fetched_file]

        version_identification.fetch_files = fetch_files

        version = await version_identification.identify_version("target")

        self.assertEqual(version, "2.0.x")

    @async_test()
    async def test_identify_version_return_message_if_no_minor_version_can_be_identify(self):
        style_css_signature = FileSignature(hash=hash_data(self.style_css_fetched_file.data), versions=["1.0", "1.1"])
        style_css_file = File(path="style.css", signatures=[style_css_signature])

        file_list = FileList(producer="unittest", key="wordpress", files=[style_css_file])
        version_identification = VersionIdentification(self.hammertime)
        version_identification.file_list = file_list

        async def fetch_files(*args):
            return [self.style_css_fetched_file]

        version_identification.fetch_files = fetch_files

        version = await version_identification.identify_version("target")

        self.assertEqual(version, "could not identify target wordpress version")



    def test_load_versions_signatures(self):
        filename = join(dirname(__file__), "samples/vane2_versions.json")

        self.version_identification.load_files_signatures(filename)

        file_list = FileListSchema().dump(self.version_identification.file_list).data
        file_list = wrap_lists_in_unordered_lists(file_list)

        self.assertEqual(file_list, {"key": "wordpress", "producer": "unittest", "files":
            [{"path": "readme.html", "signatures": [{"hash": "1234", "algo": "SHA256", "versions": ["1.0"]},
                                                    {"hash": "2345", "algo": "SHA256", "versions": ["2.0"]}]},
             {"path": "file.js", "signatures": [{"hash": "4321", "algo": "SHA256", "versions": ["1.0", "2.0"]}]}]})

    def test_get_common_minor_version(self):
        versions1_3 = ["1.3.0", "1.3.1", "1.3.2", "1.3.6"]
        versions2_5 = ["2.5.1", "2.5.3", "2.5.6"]
        versions_mixed = ["1.9.2", "4.5.1", "6.7.2"]

        minor_version1_3 = self.version_identification._get_common_minor_version(versions1_3)
        minor_version2_5 = self.version_identification._get_common_minor_version(versions2_5)
        no_minor_version = self.version_identification._get_common_minor_version(versions_mixed)

        self.assertEqual(minor_version1_3, "1.3.x")
        self.assertEqual(minor_version2_5, "2.5.x")
        self.assertIsNone(no_minor_version)
