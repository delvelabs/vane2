from unittest import TestCase
from unittest.mock import MagicMock, call
from unittest import mock
from vane.versionidentification import VersionIdentification, FetchedFile
from openwebvulndb.common.models import FileSignature, File, FileList
from openwebvulndb.common.schemas import FileListSchema
from os.path import join, dirname
from fixtures import wrap_lists_in_unordered_lists
from aiohttp.test_utils import make_mocked_coro, loop_context
import asyncio


class TestVersionIdentification(TestCase):

    def setUp(self):
        self.hammertime = MagicMock()

        self.version_identification = VersionIdentification(self.hammertime)

        self.readme_fetched_file = FetchedFile(path="readme.html", hash="12345")
        self.style_css_fetched_file = FetchedFile(path="style.css", hash="09876")

        self.readme_1_signature = FileSignature(hash=self.readme_fetched_file.hash, versions=["1.0"])
        self.readme_2_signature = FileSignature(hash="23456", versions=["2.0"])
        self.readme_file = File(path="readme.html", signatures=[self.readme_1_signature, self.readme_2_signature])

        self.style_css_signature = FileSignature(hash=self.style_css_fetched_file.hash, versions=["1.0", "2.0"])
        self.style_css_file = File(path="style.css", signatures=[self.style_css_signature])

        self.version_identification.file_list = FileList(key="", producer="", files=[self.readme_file,
                                                                                     self.style_css_file])

    @mock.patch('asyncio.wait', new=make_mocked_coro(([], None)))
    def test_fetch_files_make_request_to_hammertime(self):
        target = "http://www.target.url/"

        with loop_context() as loop:
            loop.run_until_complete(self.version_identification.fetch_files(target))

            self.hammertime.request.assert_has_calls([
                call(target + "readme.html", arguments={'file_path': self.readme_file.path, 'hash_algo': "SHA256"}),
                call(target + "style.css", arguments={'file_path': self.style_css_file.path, 'hash_algo': "SHA256"})])

    def test_fetch_files_return_fetched_files(self):
        target = "http://www.target.url/"

        readme_http_entry = MagicMock()
        readme_http_entry.arguments = {"file_path": "readme.html", 'hash': "12345"}

        style_http_entry = MagicMock()
        style_http_entry.arguments = {"file_path": "style.css", 'hash': "09876"}

        with loop_context() as loop:
            readme_result = asyncio.Future(loop=loop)
            readme_result.set_result(readme_http_entry)
            style_result = asyncio.Future(loop=loop)
            style_result.set_result(style_http_entry)

            with mock.patch('asyncio.wait', new=make_mocked_coro(([readme_result, style_result], None))):
                fetched_files = loop.run_until_complete(self.version_identification.fetch_files(target))

                fetched_readme_file = fetched_files[0]
                fetched_style_file = fetched_files[1]
                self.assertEqual(fetched_style_file.path, "style.css")
                self.assertEqual(fetched_style_file.hash, "09876")
                self.assertEqual(fetched_readme_file.path, "readme.html")
                self.assertEqual(fetched_readme_file.hash, "12345")

    @mock.patch('asyncio.wait', new=make_mocked_coro(([], None)))
    def test_fetch_files_join_target_url_and_file_path(self):
        url_ending_with_slash = "http://wp.dev.wardenscanner.com/"
        url_without_ending_slash = "http://wp.dev.wardenscanner.com/"

        with loop_context() as loop:
            loop.run_until_complete(self.version_identification.fetch_files(url_ending_with_slash))
            loop.run_until_complete(self.version_identification.fetch_files(url_without_ending_slash))

            readme_args = {'file_path': self.readme_file.path, 'hash_algo': "SHA256"}
            style_css_args = {'file_path': self.style_css_file.path, 'hash_algo': "SHA256"}
            self.hammertime.request.assert_has_calls(
                [call("http://wp.dev.wardenscanner.com/readme.html", arguments=readme_args),
                 call("http://wp.dev.wardenscanner.com/style.css", arguments=style_css_args),
                 call("http://wp.dev.wardenscanner.com/readme.html", arguments=readme_args),
                 call("http://wp.dev.wardenscanner.com/style.css", arguments=style_css_args)])

    def test_get_possible_versions_for_fetched_file(self):
        file_list = FileList(key="wordpress", producer="", files=[self.readme_file])
        self.version_identification.file_list = file_list

        versions = self.version_identification._get_possible_versions_for_fetched_file(self.readme_fetched_file)

        self.assertEqual(versions, self.readme_1_signature.versions)

    def test_identify_version(self):
        file_list = FileList(producer="unittest", key="wordpress", files=[self.readme_file, self.style_css_file])
        self.version_identification.file_list = file_list

        async def fetch_files(*args):
            return [self.readme_fetched_file, self.style_css_fetched_file]

        self.version_identification.fetch_files = fetch_files

        with loop_context() as loop:
            version = loop.run_until_complete(self.version_identification.identify_version("target"))

            self.assertEqual(version, "1.0")

    def test_identify_version_find_closest_match_when_one_file_is_missing(self):
        login_js_signature_1 = FileSignature(hash="11111", versions=["1.0"])
        login_js_signature_2 = FileSignature(hash="22222", versions=["2.0"])
        login_js_file = File(path="login.js", signatures=[login_js_signature_1, login_js_signature_2])

        file_list = FileList(producer="unittest", key="wordpress", files=[self.readme_file, self.style_css_file,
                                                                          login_js_file])

        self.version_identification.file_list = file_list
        fetched_login = FetchedFile(path="login.js", hash="11111")

        async def fetch_files(*args):
            return [fetched_login, self.style_css_fetched_file]
        self.version_identification.fetch_files = fetch_files

        with loop_context() as loop:
            version = loop.run_until_complete(self.version_identification.identify_version("target"))

            self.assertEqual(version, "1.0")

    def test_identify_version_return_lowest_version_if_cant_identify_precise_version(self):
        style_css_signature = FileSignature(hash=self.style_css_fetched_file.hash, versions=["2.0.0", "2.0.1"])
        style_css_file = File(path="style.css", signatures=[style_css_signature])

        file_list = FileList(producer="unittest", key="wordpress", files=[style_css_file])
        version_identification = VersionIdentification(self.hammertime)
        version_identification.file_list = file_list

        async def fetch_files(*args):
            return [self.style_css_fetched_file]

        version_identification.fetch_files = fetch_files

        with loop_context() as loop:
            version = loop.run_until_complete(version_identification.identify_version("target"))

            self.assertEqual(version, "2.0.0")

    def test_identify_version_return_none_if_no_version_found(self):
        file_list = FileList(producer="unittest", key="wordpress", files=[self.style_css_file])
        version_identification = VersionIdentification(self.hammertime)
        version_identification.file_list = file_list

        async def fetch_files(*args):
            return [self.readme_fetched_file]

        version_identification.fetch_files = fetch_files
        with loop_context() as loop:
            version = loop.run_until_complete(version_identification.identify_version("target"))

            self.assertIsNone(version)

    def test_load_versions_signatures(self):
        filename = join(dirname(__file__), "samples/vane2_versions.json")

        self.version_identification.load_files_signatures(filename)

        file_list = FileListSchema().dump(self.version_identification.file_list).data
        file_list = wrap_lists_in_unordered_lists(file_list)

        self.assertEqual(file_list, {"key": "wordpress", "producer": "unittest", "files":
            [{"path": "readme.html", "signatures": [{"hash": "1234", "algo": "SHA256", "versions": ["1.0"]},
                                                    {"hash": "2345", "algo": "SHA256", "versions": ["2.0"]}]},
             {"path": "file.js", "signatures": [{"hash": "4321", "algo": "SHA256", "versions": ["1.0", "2.0"]}]}]})

    def test_get_lowest_version(self):
        versions = ["1.3.0", "1.3.1", "4.7.0", "2.7.6", "1.0.12"]

        version = self.version_identification._get_lowest_version(versions)

        self.assertEqual(version, "1.0.12")
