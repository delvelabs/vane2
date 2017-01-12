from unittest import TestCase
from os.path import join, dirname
from vane.passivepluginsfinder import PassivePluginsFinder
from unittest.mock import MagicMock


class TestPassivePluginsFinder(TestCase):

    def setUp(self):
        self.plugin_finder = PassivePluginsFinder()
        self.plugin_finder.set_plugins_database(MagicMock())

    def test_find_plugins_in_elements_find_plugin_references_in_page_source(self):
        sample_page0 = join(dirname(__file__), "samples/delvelabs.html")
        sample_page1 = join(dirname(__file__), "samples/starwars.html")
        sample_page2 = join(dirname(__file__), "samples/playstation.html")
        sample_page3 = join(dirname(__file__), "samples/bata.html")
        self.plugin_finder.plugins_database.get_plugins.return_value = ["disqus-comment-system", "mobile-navigation", "cyclone-slider-2",
                                                     "sitepress-multilingual-cms", "wp-jquery-lightbox", "panopress",
                                                     "yet-another-related-posts-plugin", "wp-polls", "wp-postratings",
                                                     "lift-search", "jetpack", "audio-player", "captcha",
                                                     "validated-field-for-acf"]

        plugins_in_page0 = self.plugin_finder._find_plugins_in_elements(sample_page0)
        plugins_in_page1 = self.plugin_finder._find_plugins_in_elements(sample_page1)
        plugins_in_page2 = self.plugin_finder._find_plugins_in_elements(sample_page2)
        plugins_in_page3 = self.plugin_finder._find_plugins_in_elements(sample_page3)

        self.assertIn("disqus-comment-system", plugins_in_page0)
        self.assertIn("mobile-navigation", plugins_in_page0)
        self.assertEqual(len(plugins_in_page0), 2)

        self.assertIn("cyclone-slider-2", plugins_in_page1)
        self.assertIn("sitepress-multilingual-cms", plugins_in_page1)
        self.assertIn("wp-jquery-lightbox", plugins_in_page1)
        self.assertIn("panopress", plugins_in_page1)
        self.assertIn("yet-another-related-posts-plugin", plugins_in_page1)
        self.assertEqual(len(plugins_in_page1), 5)

        self.assertIn("wp-polls", plugins_in_page2)
        self.assertIn("wp-postratings", plugins_in_page2)
        self.assertIn("lift-search", plugins_in_page2)
        self.assertIn("jetpack", plugins_in_page2)
        self.assertIn("audio-player", plugins_in_page2)
        self.assertEqual(len(plugins_in_page2), 5)

        self.assertIn("captcha", plugins_in_page3)
        self.assertIn("validated-field-for-acf", plugins_in_page3)
        self.assertEqual(len(plugins_in_page3), 2)

    def test_find_plugins_in_comments_find_in_page_source_comments(self):
        sample_page = join(dirname(__file__), "samples/comment.html")
        self.plugin_finder.plugins_database.get_plugins.return_value = ["w3-total-cache"]

        self.assertIn("w3-total-cache", self.plugin_finder._find_plugins_in_comments(sample_page))

    def test_find_plugins_in_comments_parse_comments_outside_html_closing_tag(self):
        sample_page = join(dirname(__file__), "samples/timeinc.html")
        self.plugin_finder.plugins_database.get_plugins.return_value = ["wp-super-cache"]

        plugins = self.plugin_finder._find_plugins_in_comments(sample_page)

        self.assertEqual(["wp-super-cache"], plugins)

    def test_plugin_names_equal_ignore_case(self):
        name0 = "Mobile-Navigation"
        name1 = "mobile-navigation"

        self.assertTrue(self.plugin_finder._plugin_names_equal(name0, name1))

    def test_plugin_names_equal_ignore_whitespace(self):
        name0 = "mobile navigation"
        name1 = "mobile-navigation"

        self.assertTrue(self.plugin_finder._plugin_names_equal(name0, name1))

    def test_plugin_names_equal_ignore_hyphens(self):
        name0 = "mobilenavigation"
        name1 = "mobile-navigation"

        self.assertTrue(self.plugin_finder._plugin_names_equal(name0, name1))

    def test_get_plugin_name_in_comment_text_find_plugin_name_in_comment(self):
        plugin_name0 = "google analytics"
        plugin_name1 = "yoast seo"
        plugin_name2 = "wp-parsely"
        plugin_name3 = "w3-total-cache"
        plugin_name4 = "comscore-tag"
        plugin_name5 = "add-meta-tags"
        self.plugin_finder.plugins_database.get_plugins.return_value = [plugin_name0, plugin_name1, plugin_name2,
                                                                        plugin_name3, plugin_name4, plugin_name5]
        comment0 = "This site uses the Google Analytics by MonsterInsights plugin v5.5.4 - Universal enabled - https://www.monsterinsights.com/"
        comment1 = "This site is optimized with the Yoast SEO plugin v4.0.2 - https://yoast.com/wordpress/plugins/seo/"
        comment2 = " BEGIN wp-parsely Plugin Version 1.10.2 "
        comment3 = " / Yoast SEO plugin. "
        comment4 = """ Performance optimized by W3 Total Cache. Learn more: http://www.w3-edge.com/wordpress-plugins/
                       Page Caching using memcached Database Caching 20/145 queries in 0.172 seconds using memcached
                       Object Caching 3311/3449 objects using memcached
                       Served from: www.bbcamerica.com @ 2017-01-11 10:56:28 by W3 Total Cache"""
        comment5 = " Begin comScore Tag "
        comment6 = " BEGIN Metadata added by the Add-Meta-Tags WordPress plugin "

        self.assertEqual(self.plugin_finder._get_plugin_name_from_comment_text(comment0), plugin_name0)
        self.assertEqual(self.plugin_finder._get_plugin_name_from_comment_text(comment1), plugin_name1)
        self.assertEqual(self.plugin_finder._get_plugin_name_from_comment_text(comment2), plugin_name2)
        self.assertEqual(self.plugin_finder._get_plugin_name_from_comment_text(comment3), plugin_name1)
        self.assertEqual(self.plugin_finder._get_plugin_name_from_comment_text(comment5), plugin_name4)
        self.assertEqual(self.plugin_finder._get_plugin_name_from_comment_text(comment6), plugin_name5)

    def test_get_plugin_name_from_comment_text_find_plugin_in_url_contained_in_comment(self):
        comment_with_url = "[if lte IE 8]><link rel='stylesheet' id='jetpack-carousel-ie8fix-css'  \
                            href='http://s1.wp.com/wp-content/mu-plugins/carousel/jetpack-carousel-ie8fix.css?m=14126188\
                            25h&#038;ver=20121024' type='text/css' media='all' /><![endif]"
        self.plugin_finder.plugins_database.get_plugins.return_value = ["carousel"]

        plugin_name = self.plugin_finder._get_plugin_name_from_comment_text(comment_with_url)

        self.assertEqual(plugin_name, "carousel")

    def test_get_plugin_name_from_plugin_url_return_none_if_no_match_in_plugin_database(self):
        self.plugin_finder.plugins_database.get_plugins.return_value = ["w3-total-cache"]
        plugin_url = "http://www.mywebsite.com/wp-content/plugins/some-plugin/somefilename.php"

        self.assertIsNone(self.plugin_finder._get_plugin_name_from_url(plugin_url))

    def test_get_plugin_name_from_plugin_url_return_name_from_plugin_database_if_match_found(self):
        self.plugin_finder.plugins_database.get_plugins.return_value = ["w3-total-cache"]
        plugin_url = "http://www.mywebsite.com/wp-content/plugins/w3-total-cache/somefilename.php"

        self.assertEqual(self.plugin_finder._get_plugin_name_from_url(plugin_url), "w3-total-cache")

    def test_is_plugin_url_return_false_if_invalid_url(self):
        url = "abialguabg ailuehgfiub"

        self.assertFalse(self.plugin_finder._is_plugin_url(url))

    def test_is_plugin_url_return_true_if_url_contains_existing_plugin_name(self):
        self.plugin_finder.plugins_database.get_plugins.return_value = ["w3-total-cache"]
        plugin_url = "http://www.mywebsite.com/wp-content/plugins/w3-total-cache/somefilename.php"

        self.assertTrue(self.plugin_finder._is_plugin_url(plugin_url))

    def test_is_plugin_url_return_false_if_url_doesnt_contain_existing_plugin_name(self):
        self.plugin_finder.plugins_database.get_plugins.return_value = ["w3-total-cache"]
        plugin_url = "http://www.mywebsite.com/wp-content/plugins/some-plugin/somefilename.php"

        self.assertFalse(self.plugin_finder._is_plugin_url(plugin_url))

    def test_get_plugin_url_find_plugin_in_mu_plugins_directory(self):
        url = "https://s1.wp.com/wp-content/mu-plugins/carousel/jetpack-carousel.css?m=1481571546h&cssminify=yes"
        self.plugin_finder.plugins_database.get_plugins.return_value = ["carousel"]

        self.assertEqual(self.plugin_finder._get_plugin_name_from_url(url), "carousel")

    def test_find_plugin_name_in_string_only_return_full_match(self):
        possibilities = ["recaptcha", "spam-captcha", "pluscaptcha", "wp-captcha"]
        self.plugin_finder.plugins_database.get_plugins.return_value = possibilities
        string = "This site uses the captcha plugin."

        self.assertIsNone(self.plugin_finder._find_plugin_name_in_string(string))

    def test_find_plugin_name_in_string_return_longest_match(self):
        possibilities = ["captcha", "wp-captcha"]
        self.plugin_finder.plugins_database.get_plugins.return_value = possibilities
        string = "This site uses the wp-captcha plugin."

        self.assertEqual(self.plugin_finder._find_plugin_name_in_string(string), "wp-captcha")
