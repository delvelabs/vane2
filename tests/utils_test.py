from unittest import TestCase
from vane.utils import validate_url, normalize_url


class TestUtils(TestCase):
    
    def test_validate_url_return_false_if_malformed_url(self):
        url0 = "not a valid url"
        url1 = "www.test"
        url2 = "test.com"
        url3 = "test://www.test.com"
        url4 = "https//www.test.com"

        self.assertFalse(validate_url(url0))
        self.assertFalse(validate_url(url1))
        self.assertFalse(validate_url(url2))
        self.assertFalse(validate_url(url3))
        self.assertFalse(validate_url(url4))

    def test_normalize_url_append_slash_if_url_path_is_not_empty_and_not_ending_with_slash(self):
        url0 = "http://wp.dev.wardenscanner.com/"
        url1 = "http://wp.dev.wardenscanner.com"
        url2 = "http://127.0.0.1/wordpress"
        url3 = "http://127.0.0.1/wordpress/"

        url0 = normalize_url(url0)
        url1 = normalize_url(url1)
        url2 = normalize_url(url2)
        url3 = normalize_url(url3)

        self.assertEqual(url0, "http://wp.dev.wardenscanner.com/")
        self.assertEqual(url1, "http://wp.dev.wardenscanner.com/")
        self.assertEqual(url2, "http://127.0.0.1/wordpress/")
        self.assertEqual(url3, "http://127.0.0.1/wordpress/")
