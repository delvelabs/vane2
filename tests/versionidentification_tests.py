from unittest import TestCase
from unittest.mock import MagicMock, call
from vane.versionidentification import VersionIdentification
import hashlib
from common.models import Signature


class TestVersionIdentification(TestCase):

    def setUp(self):
        self.versions_list = MagicMock()
        self.hammertime = MagicMock()
        self.version_identification = VersionIdentification(self.versions_list, self.hammertime)
        self.version_identification.get_files_to_fetch = MagicMock()

    def test_fetch_files_for_version_identification(self):
        self.version_identification.get_files_to_fetch.return_value = ["readme.html", "style.css", "wp-include/file.js"]
        target = "http://www.target.url/"

        for file in self.version_identification.fetch_files(target):
            pass

        self.hammertime.request.assert_has_calls([call(target + "readme.html"), call(target + "style.css"),
                                                  call(target + "wp-include/file.js")])
        self.hammertime.successful_requests.assert_any_call()

    def test_get_file_hash_return_valid_hash(self):
        file = VersionIdentification.File("readme.html", b"This is the readme file.")
        hasher = hashlib.sha256()
        hasher.update(file.data)
        expected_file_hash = hasher.hexdigest()

        file_hash = self.version_identification.get_file_hash(file, "sha256")

        self.assertEqual(file_hash, expected_file_hash)

    def test_hash_files_hash_all_file_in_version_signature_with_good_algo(self):
        readme = VersionIdentification.File("readme.html", b"This is the readme file.")
        style_css = VersionIdentification.File("style.css", b"This is the style file.")
        file_not_in_signature = VersionIdentification.File("file.js", b"javascript file.")
        files = [readme, style_css, file_not_in_signature]
        readme_signature = Signature(path="readme.html", hash=hashlib.sha256(b"This is the readme file.").hexdigest())
        style_css_signature = Signature(path="style.css", hash=hashlib.md5(b"This is the style file.").hexdigest(), algo="MD5")
        signatures = [readme_signature, style_css_signature]

        self.version_identification.hash_files(files, signatures)

        self.assertEqual(readme.algo, readme_signature.algo)
        self.assertEqual(readme.hash, readme_signature.hash)
        self.assertEqual(style_css.algo, style_css_signature.algo)
        self.assertEqual(style_css.hash, style_css_signature.hash)
        self.assertIsNone(file_not_in_signature.algo)
        self.assertIsNone(file_not_in_signature.hash)
