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
from unittest.mock import MagicMock

from vane.passivethemesfinder import PassiveThemesFinder
from vane.theme import Theme

from os.path import join, dirname

from fixtures import html_file_to_hammertime_response

class TestPassiveThemesFinder(TestCase):

    def setUp(self):
        self.themes_finder = PassiveThemesFinder()

    def test_contains_theme_url_return_false_if_not_valid_theme_url(self):
        url = "https://www.url.com/path/to/page/"

        self.assertFalse(self.themes_finder._contains_theme_url(url))

    def test_contains_theme_url_return_true_if_theme_url_in_string(self):
        url = "A string with a theme url. http://static.blog.playstation.com/wp-content/themes/twenty11/ie8.css?m=1480446942"

        self.assertTrue(self.themes_finder._contains_theme_url(url))

    def test_contains_theme_url_return_true_if_vip_theme_url_in_string(self):
        url = "A string with a vip theme url https://s0.wp.com/wp-content/themes/vip/fortune/static/js/html5shiv.min.js " \
              "and random characters at the end."

        self.assertTrue(self.themes_finder._contains_theme_url(url))

    def test_contains_theme_url_return_true_if_theme_url_is_relative(self):
        relative_url = "this is the theme url: /wp-content/themes/my-theme/style.css"

        self.assertTrue(self.themes_finder._contains_theme_url(relative_url))

    def test_get_theme_url_from_string_remove_beginning_of_string_not_part_of_the_url(self):
        string = 'beginning of string ... http://static.blog.playstation.com/wp-content/themes/twenty11'

        self.assertEqual(self.themes_finder._get_theme_url_from_string(string),
                         "http://static.blog.playstation.com/wp-content/themes/twenty11")

    def test_get_theme_url_from_string_remove_part_after_theme_name(self):
        url = "http://static.blog.playstation.com/wp-content/themes/twenty11/ie8.css?m=1480446942"

        self.assertEqual(self.themes_finder._get_theme_url_from_string(url),
                         "http://static.blog.playstation.com/wp-content/themes/twenty11")

    def test_get_theme_url_from_string_return_return_relative_url(self):
        relative_url = "this is the theme url: /wp-content/themes/my-theme/style.css"

        self.assertEqual(self.themes_finder._get_theme_url_from_string(relative_url), "/wp-content/themes/my-theme")

    def test_list_themes_find_themes_in_page_source(self):
        sample_page0 = join(dirname(__file__), "samples/playstation.html")
        sample_page1 = join(dirname(__file__), "samples/delvelabs.html")

        page0_hammertime_response = html_file_to_hammertime_response(sample_page0)
        page1_hammertime_response = html_file_to_hammertime_response(sample_page1)

        themes0 = self.themes_finder.list_themes(page0_hammertime_response)
        themes1 = self.themes_finder.list_themes(page1_hammertime_response)

        self.assertIn("twenty11", (theme.name for theme in themes0))
        self.assertIn("kratos", (theme.name for theme in themes0))
        self.assertEqual(len(themes0), 2)

        self.assertIn("delvelabs", (theme.name for theme in themes1))
        self.assertEqual(len(themes1), 1)

    def test_list_themes_find_theme_in_comments_with_theme_url(self):
        sample_page = join(dirname(__file__), "samples/comment.html")

        hammertime_response = html_file_to_hammertime_response(sample_page)

        themes = self.themes_finder.list_themes(hammertime_response)

        self.assertIn("twenty11", (theme.name for theme in themes))
