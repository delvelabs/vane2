from unittest import TestCase
from os.path import join, dirname
from vane.passivepluginsfinder import PassivePluginsFinder
from vane.plugin import Plugin
from unittest.mock import MagicMock
from lxml import etree


class TestPassivePluginsFinder(TestCase):

    def setUp(self):
        self.plugin_finder = PassivePluginsFinder(MagicMock(), MagicMock())

    def test_find_plugins_in_elements_find_plugin_references_in_page_source(self):
        sample_page0 = join(dirname(__file__), "samples/delvelabs.html")
        sample_page1 = join(dirname(__file__), "samples/starwars.html")
        sample_page2 = join(dirname(__file__), "samples/playstation.html")
        self.plugin_finder.plugins_database.get_plugin_names.return_value = ["disqus-comment-system", "yoast-seo", "jetpack",
                                                                        "google-analytics", "cyclone-slider-2",
                                                                        "sitepress-multilingual-cms", "audio-player"
                                                                        "wp-jquery-lightbox", "panopress", "wp-polls",
                                                                        "yet-another-related-posts-plugin",
                                                                        "wp-postratings", "lift-search"]
        plugins_in_page0 = self.plugin_finder.list_plugins(sample_page0)
        plugins_in_page1 = self.plugin_finder.list_plugins(sample_page1)
        plugins_in_page2 = self.plugin_finder.list_plugins(sample_page2)

        self.assertIn(Plugin.from_name("disqus-comment-system"), plugins_in_page0)
        self.assertIn(Plugin.from_name("yoast-seo"), plugins_in_page0)
        self.assertIn(Plugin.from_name("google-analytics"), plugins_in_page0)
        self.assertEqual(len(plugins_in_page0), 3)

        self.assertIn(Plugin.from_name("cyclone-slider-2"), plugins_in_page1)
        self.assertIn(Plugin.from_name("sitepress-multilingual-cms"), plugins_in_page1)
        self.assertIn(Plugin.from_name("wp-jquery-lightbox"), plugins_in_page1)
        self.assertIn(Plugin.from_name("panopress"), plugins_in_page1)
        self.assertIn(Plugin.from_name("yet-another-related-posts-plugin"), plugins_in_page1)
        self.assertIn(Plugin.from_name("yoast-seo"), plugins_in_page1)
        self.assertIn(Plugin.from_name("google-analytics"), plugins_in_page1)
        self.assertEqual(len(plugins_in_page1), 7)

        self.assertIn(Plugin.from_name("wp-polls"), plugins_in_page2)
        self.assertIn(Plugin.from_name("wp-postratings"), plugins_in_page2)
        self.assertIn(Plugin.from_name("lift-search"), plugins_in_page2)
        self.assertIn(Plugin.from_name("jetpack"), plugins_in_page2)
        self.assertIn(Plugin.from_name("audio-player"), plugins_in_page2)
        self.assertIn(Plugin.from_name("google-analytics"), plugins_in_page2)
        self.assertIn(Plugin.from_name("scea-omniture"), plugins_in_page2)
        self.assertIn(Plugin.from_name("image-rotator-2"), plugins_in_page2)
        self.assertEqual(len(plugins_in_page2), 8)

    def test_search_in_element_attributes_find_plugins_from_plugin_url_in_attributes_values(self):
        element = etree.fromstring('<img src="http://static.blog.playstation.com/wp-content/plugins/wp-postratings/images/custom/rating_on.png"/>')

        plugin = next(self.plugin_finder._search_in_element_attributes(element))

        self.assertEqual(plugin.name, "wp-postratings")

    def test_find_plugins_in_comments_find_plugin_from_url_in_comment(self):
        sample_page = join(dirname(__file__), "samples/comment.html")

        plugins = self.plugin_finder._find_plugins_in_comments(sample_page)

        self.assertIn("carousel", [plugin.name for plugin in plugins])

    def test_search_plugin_in_comments_outside_document_parse_comments_outside_html_closing_tag(self):
        sample_page = join(dirname(__file__), "samples/timeinc.html")
        self.plugin_finder.plugins_database.get_plugin_names.return_value = ["wp-super-cache"]

        plugins = self.plugin_finder._search_plugin_in_comments_outside_document(sample_page)

        self.assertIn("wp-super-cache", [plugin.name for plugin in plugins])

    def test_find_plugin_name_in_comment_find_plugin_name_in_comment_that_match_plugin_name_in_database(self):
        plugin_name0 = "google analytics"
        plugin_name1 = "yoast seo"
        plugin_name2 = "wp-parsely"
        plugin_name4 = "w3-total-cache"
        plugin_name5 = "comscore-tag"
        plugin_name6 = "add-meta-tags"
        self.plugin_finder.plugins_database.get_plugin_names.return_value = [plugin_name0, plugin_name1, plugin_name2,
                                                                        plugin_name4, plugin_name5, plugin_name6]
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

        plugin0 = self.plugin_finder._find_plugin_name_in_comment(comment0)
        plugin1 = self.plugin_finder._find_plugin_name_in_comment(comment1)
        plugin2 = self.plugin_finder._find_plugin_name_in_comment(comment2)
        plugin3 = self.plugin_finder._find_plugin_name_in_comment(comment3)
        plugin4 = self.plugin_finder._find_plugin_name_in_comment(comment4)
        plugin5 = self.plugin_finder._find_plugin_name_in_comment(comment5)
        plugin6 = self.plugin_finder._find_plugin_name_in_comment(comment6)

        self.assertEqual(plugin0, plugin_name0)
        self.assertEqual(plugin1, plugin_name1)
        self.assertEqual(plugin2, plugin_name2)
        self.assertEqual(plugin3, plugin_name1)
        self.assertEqual(plugin4, plugin_name4)
        self.assertEqual(plugin5, plugin_name5)
        self.assertEqual(plugin6, plugin_name6)

    def test_contains_plugin_url_return_false_if_no_valid_url(self):
        url = "http://www.mywebsite.com/contact-us.html"

        self.assertFalse(self.plugin_finder._contains_plugin_url(url))

    def test_contains_plugin_url_return_true_if_string_contains_relative_plugin_url(self):
        url = "/wp-content/plugins/my-plugin/file.php"

        self.assertTrue(self.plugin_finder._contains_plugin_url(url))

    def test_contains_plugin_url_return_true_if_string_contains_plugin_url(self):
        plugin_url = "http://www.mywebsite.com/wp-content/plugins/w3-total-cache/somefilename.php"

        self.assertTrue(self.plugin_finder._contains_plugin_url(plugin_url))

    def test_contains_plugin_url_return_true_if_string_contains_mu_plugin_url(self):
        plugin_url = "http://www.mywebsite.com/wp-content/mu-plugins/some-plugin/somefilename.php"

        self.assertTrue(self.plugin_finder._contains_plugin_url(plugin_url))

    def test_get_plugin_url_from_string_remove_junk_before_url(self):
        url = "junk before url: https://s1.wp.com/wp-content/mu-plugins/carousel"

        self.assertEqual(self.plugin_finder._get_plugin_url_from_string(url),
                         "https://s1.wp.com/wp-content/mu-plugins/carousel")

    def test_get_plugin_url_from_string_remove_part_after_plugin_name(self):
        url = "https://s1.wp.com/wp-content/mu-plugins/carousel/jetpack-carousel.css?m=1481571546h&cssminify=yes"

        self.assertEqual(self.plugin_finder._get_plugin_url_from_string(url),
                         "https://s1.wp.com/wp-content/mu-plugins/carousel")

    def test_get_plugin_url_from_string_work_with_relative_plugin_url(self):
        string = "this is a relative url: /wp-content/plugins/my-plugin/file.php"

        url = self.plugin_finder._get_plugin_url_from_string(string)

        self.assertEqual(url, "/wp-content/plugins/my-plugin")

    def test_find_existing_plugin_name_in_string_only_return_full_match(self):
        possibilities = ["recaptcha", "spam-captcha", "pluscaptcha", "wp-captcha"]
        self.plugin_finder.plugins_database.get_plugin_names.return_value = possibilities
        string = "This site uses the captcha plugin."

        self.assertIsNone(self.plugin_finder._find_existing_plugin_name_in_string(string))

    def test_find_existing_plugin_name_in_string_return_longest_match(self):
        possibilities = ["captcha", "wp-captcha"]
        self.plugin_finder.plugins_database.get_plugin_names.return_value = possibilities
        string = "This site uses the wp-captcha plugin."

        self.assertEqual(self.plugin_finder._find_existing_plugin_name_in_string(string), "wp-captcha")

    def test_find_possible_plugin_name_in_comment_log_plugin_name_in_comment_with_plugin_word(self):
        comment0 = "This site uses the Google Analytics by MonsterInsights plugin v5.5.4 - Universal enabled - https://www.monsterinsights.com/"
        comment1 = "This site is optimized with the Yoast SEO plugin v4.0.2 - https://yoast.com/wordpress/plugins/seo/"
        comment2 = " BEGIN wp-parsely Plugin Version 1.10.2 "
        comment_without_plugin = " Random string iuehaguihug"
        logger = MagicMock()
        self.plugin_finder.set_logger(logger)

        self.plugin_finder._find_possible_plugin_name_in_comment(comment0)
        logger.add_plugin.assert_called_with("the google analytics")

        self.plugin_finder._find_possible_plugin_name_in_comment(comment1)
        logger.add_plugin.assert_called_with("the yoast seo")

        self.plugin_finder._find_possible_plugin_name_in_comment(comment2)
        logger.add_plugin.assert_called_with("begin wp-parsely")

        logger.reset_mock()
        self.plugin_finder._find_possible_plugin_name_in_comment(comment_without_plugin)
        logger.add_plugin.assert_not_called()
