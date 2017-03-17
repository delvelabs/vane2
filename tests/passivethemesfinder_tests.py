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
from openwebvulndb.common.models import MetaList, Meta
from vane.passivethemesfinder import PassiveThemesFinder

from os.path import join, dirname

from fixtures import html_file_to_hammertime_response

class TestPassiveThemesFinder(TestCase):

    def setUp(self):
        meta_list = MetaList(key="themes", metas=[Meta(key="themes/twenty11"), Meta(key="themes/kratos")])
        self.themes_finder = PassiveThemesFinder(meta_list)

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

    def test_get_theme_url_from_string_works_with_relative_url(self):
        relative_url = "this is the theme url: /wp-content/themes/my-theme/style.css"

        self.assertEqual(self.themes_finder._get_theme_url_from_string(relative_url), "/wp-content/themes/my-theme")

    def test_list_themes_return_list_of_theme_keys_found_in_page_source_that_exist_in_metas(self):
        sample_page = join(dirname(__file__), "samples/playstation.html")
        page_hammertime_response = html_file_to_hammertime_response(sample_page)

        themes = self.themes_finder.list_themes(page_hammertime_response)

        self.assertIn("themes/twenty11", themes)
        self.assertIn("themes/kratos", themes)
        self.assertEqual(len(themes), 2)

    def test_list_themes_find_theme_in_comments_with_theme_url(self):
        sample_page = join(dirname(__file__), "samples/comment.html")
        hammertime_response = html_file_to_hammertime_response(sample_page)

        themes = self.themes_finder.list_themes(hammertime_response)

        self.assertEqual({"themes/twenty11"}, themes)

    def test_get_theme_key_from_url(self):
        url0 = "http://static.blog.playstation.com/wp-content/themes/twenty11"
        url1 = "/wp-content/themes/my-theme"

        theme0 = self.themes_finder._get_theme_key_from_url(url0)
        theme1 = self.themes_finder._get_theme_key_from_url(url1)

        self.assertEqual(theme0, "themes/twenty11")
        self.assertEqual(theme1, "themes/my-theme")
