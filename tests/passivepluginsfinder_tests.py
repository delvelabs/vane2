from unittest import TestCase
from os.path import join, dirname
from vane.passivepluginsfinder import PassivePluginsFinder
from unittest.mock import MagicMock


class TestPassivePluginsFinder(TestCase):

    def test_list_plugins_find_official_plugin_references_in_page_source(self):
        sample_page0 = join(dirname(__file__), "samples/delvelabs_homepage.html")
        sample_page1 = join(dirname(__file__), "samples/starwars.html")
        plugins_finder = PassivePluginsFinder()
        plugins_database = MagicMock()
        plugins_database.get_plugins.return_value = ["disqus-comment-system", "mobile-navigation", "cyclone-slider-2",
                                                     "sitepress-multilingual-cms", "wp-jquery-lightbox", "panopress",
                                                     "yet-another-related-posts-plugin"]
        plugins_finder.set_plugins_database(plugins_database)

        plugins_in_page0 = plugins_finder.list_plugins(sample_page0)
        plugins_in_page1 = plugins_finder.list_plugins(sample_page1)

        self.assertIn("disqus-comment-system", plugins_in_page0)
        self.assertIn("mobile-navigation", plugins_in_page0)
        self.assertEqual(len(plugins_in_page0), 2)

        self.assertIn("cyclone-slider-2", plugins_in_page1)
        self.assertIn("sitepress-multilingual-cms", plugins_in_page1)
        self.assertIn("wp-jquery-lightbox", plugins_in_page1)
        self.assertIn("panopress", plugins_in_page1)
        self.assertIn("yet-another-related-posts-plugin", plugins_in_page1)
        # TODO remove duplicates
        #self.assertEqual(len(plugins_in_page1), 5)

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
        plugins_database = MagicMock()
        plugins_database.get_plugins.return_value = ["w3-total-cache", "wp-parsely"]
        plugins_finder.set_plugins_database(plugins_database)
        plugin_name0 = "google analytics"
        plugin_name1 = "yoast seo"
        plugin_name2 = "wp-parsely"
        plugin_name3 = "w3-total-cache"
        comment0 = "This site uses the Google Analytics by MonsterInsights plugin v5.5.4 - Universal enabled - https://www.monsterinsights.com/"
        comment1 = "This site is optimized with the Yoast SEO plugin v4.0.2 - https://yoast.com/wordpress/plugins/seo/"
        comment2 = " BEGIN wp-parsely Plugin Version 1.10.2 "
        comment3 = " / Yoast SEO plugin. "
        comment4 = """ Performance optimized by W3 Total Cache. Learn more: http://www.w3-edge.com/wordpress-plugins/
                       Page Caching using memcached Database Caching 20/145 queries in 0.172 seconds using memcached
                       Object Caching 3311/3449 objects using memcached
                       Served from: www.bbcamerica.com @ 2017-01-11 10:56:28 by W3 Total Cache"""

        self.assertEqual(plugins_finder.find_plugin_in_comment(comment0), plugin_name0)
        self.assertEqual(plugins_finder.find_plugin_in_comment(comment1), plugin_name1)
        self.assertEqual(plugins_finder.find_plugin_in_comment(comment2), plugin_name2)
        self.assertEqual(plugins_finder.find_plugin_in_comment(comment3), plugin_name1)
        self.assertEqual(plugins_finder.find_plugin_in_comment(comment4), plugin_name3)
