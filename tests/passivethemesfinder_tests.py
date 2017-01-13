from unittest import TestCase
from unittest.mock import MagicMock

from vane.passivethemesfinder import PassiveThemesFinder

from os.path import join, dirname


class TestPassiveThemesFinder(TestCase):

    def setUp(self):
        self.themes_finder = PassiveThemesFinder()
        self.themes_finder.set_plugins_database(MagicMock())

    def test_is_theme_url_return_false_if_not_theme_url(self):
        url = "https://www.url.com/path/to/page/"

        self.assertFalse(self.themes_finder._is_theme_url(url))

    def test_is_theme_url_return_true_if_theme_url(self):
        url = "http://static.blog.playstation.com/wp-content/themes/twenty11/ie8.css?m=1480446942"

        self.assertTrue(self.themes_finder._is_theme_url(url))

    def test_is_theme_url_return_true_if_vip_theme_url(self):
        url = "https://s0.wp.com/wp-content/themes/vip/fortune/static/js/html5shiv.min.js"

        self.assertTrue(self.themes_finder._is_theme_url(url))

    def test_get_theme_name_from_url_find_name_in_normal_theme_url(self):
        url = "http://static.blog.playstation.com/wp-content/themes/twenty11/ie8.css?m=1480446942"
        self.themes_finder.themes_database.get_themes.return_value = ["twenty11"]

        plugin_name = self.themes_finder._get_theme_name_from_url(url)

        self.assertEqual(plugin_name, "twenty11")

    def test_get_theme_name_from_url_find_name_in_vip_theme_url(self):
        url = "https://s0.wp.com/wp-content/themes/vip/fortune/static/js/html5shiv.min.js"
        self.themes_finder.themes_database.get_themes.return_value = ["fortune"]

        plugin_name = self.themes_finder._get_theme_name_from_url(url)

        self.assertEqual(plugin_name, "fortune")

    def test_get_theme_name_from_url_return_none_if_theme_name_not_in_database(self):
        url = "https://s1.wp.com/wp-content/themes/h4/global.css?m=1420737423h&cssminify=yes"
        self.themes_finder.themes_database.get_themes.return_value = []

        plugin_name = self.themes_finder._get_theme_name_from_url(url)

        self.assertIsNone(plugin_name)

    def test_theme_names_equal_ignore_case(self):
        name0 = "my-theme"
        name1 = "My-Theme"

        self.assertTrue(self.themes_finder._theme_names_equal(name0, name1))

    def test_plugin_names_equal_ignore_whitespace(self):
        name0 = "my theme"
        name1 = "my-theme"

        self.assertTrue(self.themes_finder._theme_names_equal(name0, name1))

    def test_plugin_names_equal_ignore_hyphens(self):
        name0 = "mytheme"
        name1 = "my-theme"

        self.assertTrue(self.themes_finder._theme_names_equal(name0, name1))

    def test_list_themes_find_themes_in_page_source(self):
        sample_page = join(dirname(__file__), "samples/playstation.html")
        self.themes_finder.themes_database.get_themes.return_value = ["twenty11"]

        themes = self.themes_finder.list_themes(sample_page)

        self.assertIn("twenty11", themes)
        #self.assertIn("kratos", themes)
        self.assertEqual(len(themes), 1)

    def test_find_theme_url_in_comment(self):
        comment = '[if IE 8]><link rel="stylesheet" type="text/css" href="http://static.blog.playstation.com/wp-content/themes/twenty11/ie8.css?m=1480446942" /><![endif]'
        self.themes_finder.themes_database.get_themes.return_value = ["twenty11"]

        theme_name = self.themes_finder._find_theme_url_in_comment(comment)

        self.assertEqual(theme_name, "twenty11")

    def test_list_themes_find_theme_in_comments_with_theme_url(self):
        sample_page = join(dirname(__file__), "samples/comment.html")
        self.themes_finder.themes_database.get_themes.return_value = ["twenty11"]

        themes_list = self.themes_finder.list_themes(sample_page)

        self.assertEqual(themes_list, ["twenty11"])
