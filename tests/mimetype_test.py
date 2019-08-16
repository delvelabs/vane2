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

from vane.mimetype import convert_url_to_mimetype, match


class TestConvertExtensionToMimeType(TestCase):

    def test_return_mimetype_if_extension_has_associated_mimetype(self):
        self.assertEqual(convert_url_to_mimetype("http://example.com/test.txt"), "text/plain")
        self.assertEqual(convert_url_to_mimetype("http://example.com/test.png"), "image/png")
        self.assertEqual(convert_url_to_mimetype("http://example.com/test.jpeg"), "image/jpeg")
        self.assertEqual(convert_url_to_mimetype("http://example.com/test.css"), "text/css")
        self.assertEqual(convert_url_to_mimetype("http://example.com/test.js"), "application/javascript")
        self.assertEqual(convert_url_to_mimetype("http://example.com/test.json"), "application/json")
        self.assertEqual(convert_url_to_mimetype("http://example.com/test.html"), "text/html")

    def test_url_to_mimetype_conversion_is_case_insensitive(self):
        self.assertEqual(convert_url_to_mimetype("http://example.com/test.TXT"), "text/plain")
        self.assertEqual(convert_url_to_mimetype("http://example.com/test.JPG"), "image/jpeg")

    def test_url_to_mimetype_conversion_return_none_if_extension_has_no_mimetype(self):
        self.assertIsNone(convert_url_to_mimetype("http://example.com/test.example"))

    def test_url_to_mimetype_conversion_return_none_if_no_extension(self):
        self.assertIsNone(convert_url_to_mimetype("http://example.com/test"))

    def test_match_return_true_if_same_mime_type(self):
        self.assertTrue(match("application/javascript", "application/javascript"))
        self.assertFalse(match("application/javascript", "text/html"))

    def test_match_is_case_insensitive(self):
        self.assertTrue(match("application/javascript", "Application/JavaScript"))

    def test_match_consider_all_javascript_type_equals(self):
        self.assertTrue(match("application/javascript", "text/javascript"))
        self.assertTrue(match("application/javascript", "application/x-javascript"))
        self.assertTrue(match("text/javascript", "application/x-javascript"))
