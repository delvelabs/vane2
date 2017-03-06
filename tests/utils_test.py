from unittest import TestCase
from vane.utils import validate_url


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