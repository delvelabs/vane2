from unittest import TestCase
from os.path import join, dirname
from vane.passivepluginsfinder import PassivePluginsFinder
from unittest.mock import MagicMock


class TestPassivePluginsFinder(TestCase):

    def test_list_plugins_find_official_plugin_references_in_page_source(self):
        sample_page_file_name = join(dirname(__file__), "samples/delvelabs_homepage.html")
        plugins_finder = PassivePluginsFinder()
        plugins_database = MagicMock()
        plugins_database.get_plugins.return_value = ["disqus-comment-system", "mobile-navigation"]
        plugins_finder.set_plugins_database(plugins_database)

        plugins = plugins_finder.list_plugins(sample_page_file_name)

        self.assertIn("disqus-comment-system", plugins)
        self.assertIn("mobile-navigation", plugins)
        self.assertEqual(len(plugins), 2)

    def test_plugin_names_equal_ignore_case(self):
        name0 = "Mobile-Navigation"
        name1 = "mobile-navigation"
        plugins_finder = PassivePluginsFinder()

        self.assertTrue(plugins_finder.plugin_names_equal(name0, name1))

    def test_plugin_names_equal_ignore_whitespace(self):
        name0 = "mobile navigation"
        name1 = "mobile-navigation"
        plugins_finder = PassivePluginsFinder()

        self.assertTrue(plugins_finder.plugin_names_equal(name0, name1))

    def test_plugin_names_equal_ignore_hyphens(self):
        name0 = "mobilenavigation"
        name1 = "mobile-navigation"
        plugins_finder = PassivePluginsFinder()

        self.assertTrue(plugins_finder.plugin_names_equal(name0, name1))

    def test_find_plugin_in_comment_find_plugin_name_in_comment(self):
        plugins_finder = PassivePluginsFinder()
        plugin_name0 = "google analytics by monsterinsights"
        plugin_name1 = "yoast seo"
        comment0 = "This site uses the Google Analytics by MonsterInsights plugin v5.5.4 - Universal enabled - https://www.monsterinsights.com/"
        comment1 = "This site is optimized with the Yoast SEO plugin v4.0.2 - https://yoast.com/wordpress/plugins/seo/"

        self.assertEqual(plugins_finder.find_plugin_in_comment(comment0), plugin_name0)
        self.assertEqual(plugins_finder.find_plugin_in_comment(comment1), plugin_name1)
