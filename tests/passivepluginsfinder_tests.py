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
from os.path import join, dirname
from vane.passivepluginsfinder import PassivePluginsFinder
from lxml import etree
from openwebvulndb.common.models import Meta, MetaList
from fixtures import html_file_to_hammertime_response


class TestPassivePluginsFinder(TestCase):

    def setUp(self):
        self.plugin_finder = PassivePluginsFinder(None)

        self.yoast_seo_meta = Meta(key="plugins/wordpress-seo", name="Yoast SEO",
                                   url="https://yoast.com/wordpress/plugins/seo/#utm_source=wpadmin&#038;utm_medium="
                                       "plugin&#038;utm_campaign=wpseoplugin")
        self.google_analytics_meta = Meta(key="plugins/google-analytics-for-wordpress",
                                     name="Google Analytics by MonsterInsights",
                                     url="https://www.monsterinsights.com/pricing/#utm_source=wordpress&#038;utm_medium"
                                         "=plugin&#038;utm_campaign=wpgaplugin&#038;utm_content=v504")
        self.postratings_meta = Meta(key="plugins/wp-postratings", name="WP-PostRatings")
        self.total_cache_meta = Meta(key="plugins/w3-total-cache", name="W3 Total Cache",
                                     url="http://www.w3-edge.com/wordpress-plugins/w3-total-cache/")
        self.plugin_finder.meta_list = MetaList(key="plugins", metas=[self.yoast_seo_meta, self.google_analytics_meta,
                                                                      self.postratings_meta, self.total_cache_meta])

    def test_list_plugins_find_plugin_references_and_version_in_page_source(self):
        # yoast seo, disqus comment system and google analytics by monster insights:
        sample_page0 = join(dirname(__file__), "samples/delvelabs.html")

        # yoast seo, jm-twitter-cards (impossible à trouver?), yet-another-related-posts-plugin, cyclone-slider-2,
        # wp-jquery-lightbox, panopress, sitepress-multilingual-cms, W3 Total Cache
        # possibles: MH Cookie, DOL Web Analytics
        sample_page1 = join(dirname(__file__), "samples/starwars.html")

        # wp-polls, lift-search, wp-postratings, jetpack, Google Analytics by MonsterInsights, audio-player
        # possibles: scea-omniture, image-rotator-2
        sample_page2 = join(dirname(__file__), "samples/playstation.html")

        page0_response = html_file_to_hammertime_response(sample_page0)
        page1_response = html_file_to_hammertime_response(sample_page1)
        page2_response = html_file_to_hammertime_response(sample_page2)

        disqus_meta = Meta(key="plugins/disqus-comment-system", name="Disqus Comment System")
        jetpack_meta = Meta(key="plugins/jetpack", name="Jetpack by WordPress.com")
        cyclone_slider_meta = Meta(key="plugins/cyclone-slider-2", name="Cyclone Slider 2")
        sitepress_meta = Meta(key="plugins/sitepress-multilingual-cms")
        audio_player_meta = Meta(key="plugins/audio-player")
        lightbox_meta = Meta(key="plugins/wp-jquery-lightbox", name="WP jQuery Lightbox")
        panopress_meta = Meta(key="plugins/panopress", name="PanoPress")
        wp_polls_meta = Meta(key="plugins/wp-polls", name="WP-Polls")
        posts_plugin_meta = Meta(key="plugins/yet-another-related-posts-plugin",
                                 name="Yet Another Related Posts Plugin (YARPP)")
        lift_search_meta = Meta(key="plugins/lift-search", name="Lift: Search for WordPress")
        self.plugin_finder.meta_list.metas.extend([disqus_meta, jetpack_meta, cyclone_slider_meta, sitepress_meta,
                                                   audio_player_meta, lightbox_meta, panopress_meta, wp_polls_meta,
                                                   posts_plugin_meta, lift_search_meta])

        plugins_in_page0 = self.plugin_finder.list_plugins(page0_response)
        plugins_in_page1 = self.plugin_finder.list_plugins(page1_response)
        plugins_in_page2 = self.plugin_finder.list_plugins(page2_response)

        self.assertIn(disqus_meta.key, plugins_in_page0)
        self.assertIn(self.yoast_seo_meta.key, plugins_in_page0)
        self.assertIn(self.google_analytics_meta.key, plugins_in_page0)
        self.assertEqual(plugins_in_page0[self.yoast_seo_meta.key], "4.0.2")
        self.assertEqual(plugins_in_page0[self.google_analytics_meta.key], "5.5.4")
        self.assertEqual(len(plugins_in_page0), 3)

        self.assertIn(cyclone_slider_meta.key, plugins_in_page1)
        self.assertIn(sitepress_meta.key, plugins_in_page1)
        self.assertIn(lightbox_meta.key, plugins_in_page1)
        self.assertIn(panopress_meta.key, plugins_in_page1)
        self.assertIn(posts_plugin_meta.key, plugins_in_page1)
        self.assertIn(self.yoast_seo_meta.key, plugins_in_page1)
        self.assertEqual(plugins_in_page1[self.yoast_seo_meta.key], "3.4.1")
        self.assertIn(self.total_cache_meta.key, plugins_in_page1)
        self.assertEqual(len(plugins_in_page1), 7)

        self.assertIn(wp_polls_meta.key, plugins_in_page2)
        self.assertIn(self.postratings_meta.key, plugins_in_page2)
        self.assertIn(lift_search_meta.key, plugins_in_page2)
        self.assertIn(jetpack_meta.key, plugins_in_page2)
        self.assertIn(audio_player_meta.key, plugins_in_page2)
        self.assertIn(self.google_analytics_meta.key, plugins_in_page2)
        self.assertEqual(plugins_in_page2[self.google_analytics_meta.key], "5.5.2")
        self.assertEqual(len(plugins_in_page2), 6)

    def test_search_in_element_attributes_find_plugins_from_plugin_url_in_attributes_values(self):
        element = etree.fromstring('<img src="http://static.blog.playstation.com/wp-content/plugins/wp-postratings/images/custom/rating_on.png"/>')

        plugin_key = next(self.plugin_finder._search_in_element_attributes(element))

        self.assertEqual(plugin_key, self.postratings_meta.key)

    def test_find_existing_plugin_in_string_find_plugin_from_url_in_comment(self):
        comment = "this is a comment with a plugin url: http://www.wpsite.com/wp-content/plugins/my-plugin/script.js"
        self.plugin_finder.meta_list = MetaList(key="plugins", metas=[Meta(key="my-plugin")])

        plugin_key, version = self.plugin_finder._find_plugin_in_string(comment).popitem()

        self.assertEqual(plugin_key, "my-plugin")

    def test_search_plugin_in_comments_outside_document_parse_comments_outside_html_closing_tag(self):
        sample_page = join(dirname(__file__), "samples/starwars.html")
        response = html_file_to_hammertime_response(sample_page)

        plugins = next(self.plugin_finder._search_plugin_in_comments_outside_document(response))

        self.assertEqual(plugins, {self.total_cache_meta.key: None})

    def test_find_existing_plugin_in_string_find_plugin_in_comment_that_match_plugin_name_in_meta_list(self):
        parsely_meta = Meta(key="plugins/wp-parsely", name="Parse.ly")
        add_meta_tags_meta = Meta(key="plugins/add-meta-tags", name="Add Meta Tags")
        self.plugin_finder.meta_list.metas.extend([parsely_meta, add_meta_tags_meta])

        comment0 = "This site uses the Google Analytics by MonsterInsights plugin v5.5.4 - Universal enabled - https://www.monsterinsights.com/"
        comment1 = "This site is optimized with the Yoast SEO plugin v4.0.2 - https://yoast.com/wordpress/plugins/seo/"
        comment2 = " BEGIN wp-parsely Plugin Version 1.10.2 "
        comment3 = " / Yoast SEO plugin. "
        comment4 = " BEGIN Metadata added by the Add-Meta-Tags WordPress plugin "

        plugin0 = self.plugin_finder._find_plugin_in_string(comment0)
        plugin1 = self.plugin_finder._find_plugin_in_string(comment1)
        plugin2 = self.plugin_finder._find_plugin_in_string(comment2)
        plugin3 = self.plugin_finder._find_plugin_in_string(comment3)
        plugin4 = self.plugin_finder._find_plugin_in_string(comment4)

        self.assertEqual(plugin0, {self.google_analytics_meta.key: "5.5.4"})
        self.assertEqual(plugin1, {self.yoast_seo_meta.key: "4.0.2"})
        self.assertEqual(plugin2, {parsely_meta.key: "1.10.2"})
        self.assertEqual(plugin3, {self.yoast_seo_meta.key: None})
        self.assertEqual(plugin4, {add_meta_tags_meta.key: None})

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

    def test_find_existing_plugin_in_string_only_return_full_match(self):
        self.plugin_finder.meta_list = MetaList(key="plugins")
        self.plugin_finder.meta_list.metas = [Meta(key="plugins/recaptcha"), Meta(key="plugins/spam-captcha"),
                                              Meta(key="plugins/pluscaptcha"), Meta(key="plugins/wp-captcha"),
                                              Meta(key="plugins/typing-lag-fix-for-yoast-seo",
                                                   name="Typing Lag Fix for Yoast SEO")]
        string0 = "This site uses the captcha plugin."
        string1 = "This site is optimized with the Yoast SEO plugin v4.0.2 - https://yoast.com/wordpress/plugins/seo/"

        self.assertIsNone(self.plugin_finder._find_plugin_in_string(string0))
        self.assertIsNone(self.plugin_finder._find_plugin_in_string(string1))

    def test_find_existing_plugin_in_string_return_longest_match(self):
        self.plugin_finder.meta_list = MetaList(key="plugins")
        self.plugin_finder.meta_list.metas = [Meta(key="plugins/captcha"), Meta(key="plugins/wp-captcha")]
        string = "This site uses the wp-captcha plugin."

        key, version = self.plugin_finder._find_plugin_in_string(string).popitem()

        self.assertEqual(key, "plugins/wp-captcha")

    def test_find_existing_plugin_in_string_return_plugin_key_with_key_in_meta_that_matches_string(self):
        string0 = "BEGIN wp-parsely Plugin Version 1.10.2 "
        string1 = "This site uses the wp-captcha plugin."
        string2 = "No plugin name in this string"

        self.plugin_finder.meta_list = MetaList(key="plugins")
        self.plugin_finder.meta_list.metas.append(Meta(key="plugins/wp-parsely", name="Parse.ly"))
        self.plugin_finder.meta_list.metas.append(Meta(key="plugins/wp-captcha", name="WP Captcha"))

        plugin_key0, version = self.plugin_finder._find_plugin_in_string(string0).popitem()
        plugin_key1, version = self.plugin_finder._find_plugin_in_string(string1).popitem()
        plugin_key2 = self.plugin_finder._find_plugin_in_string(string2)

        self.assertEqual(plugin_key0, "plugins/wp-parsely")
        self.assertEqual(plugin_key1, "plugins/wp-captcha")
        self.assertIsNone(plugin_key2)

    def test_find_existing_plugin_in_string_return_plugin_key_with_name_in_meta_that_matches_string(self):
        string0 = "This site uses the Google Analytics by MonsterInsights plugin v5.5.4 - Universal enabled - https://www.monsterinsights.com/"
        string1 = "This site is optimized with the Yoast SEO plugin v4.0.2 - https://yoast.com/wordpress/plugins/seo/"
        string2 = "This string contains no plugin name."

        plugin0 = self.plugin_finder._find_plugin_in_string(string0)
        plugin1 = self.plugin_finder._find_plugin_in_string(string1)

        self.assertEqual(plugin0, {self.google_analytics_meta.key: "5.5.4"})
        self.assertEqual(plugin1, {self.yoast_seo_meta.key: "4.0.2"})
        self.assertIsNone(self.plugin_finder._find_plugin_in_string(string2))

    def test_find_existing_plugin_in_string_doesnt_find_name_that_are_part_of_larger_word(self):
        """Test that a word like 'secondary' in a comment doesn't match a plugin like 'econda'."""
        meta_list = MetaList(key="plugins", metas=[Meta(key="plugins/econda"), Meta(key="plugins/nofollow"),
                                                   Meta(key="plugins/recentcomments"), Meta(key="plugins/google")])
        self.plugin_finder.set_plugins_meta_list(meta_list)
        string0 = "secondary-toggle"
        string3 = "//fonts.googleapis.com/css"

        self.assertIsNone(self.plugin_finder._find_plugin_in_string(string0))
        self.assertIsNone(self.plugin_finder._find_plugin_in_string(string3))

    def test_find_plugin_in_string_doesnt_return_words_containing_plugin_names(self):
        meta_list = MetaList(key="plugins", metas=[Meta(key="plugins/nofollow"),
                                                   Meta(key="plugins/recentcomments")])
        self.plugin_finder.set_plugins_meta_list(meta_list)
        string1 = "external nofollow"
        string2 = "recentcomments"

        self.assertIsNone(self.plugin_finder._find_plugin_in_string(string1))
        self.assertIsNone(self.plugin_finder._find_plugin_in_string(string2))

    def test_get_plugin_key_from_plugin_url(self):
        plugin_url0 = "http://www.mywebsite.com/wp-content/plugins/w3-total-cache"
        plugin_url1 = "http://static.blog.playstation.com/wp-content/plugins/wp-postratings"

        plugin_key0 = self.plugin_finder._get_plugin_key_from_plugin_url(plugin_url0)
        plugin_key1 = self.plugin_finder._get_plugin_key_from_plugin_url(plugin_url1)

        self.assertEqual(plugin_key0, "plugins/w3-total-cache")
        self.assertEqual(plugin_key1, "plugins/wp-postratings")

    def test_extract_plugin_from_plugin_comment_pattern(self):
        plugin_string0 = "BEGIN wp-parsely Plugin Version 1.10.2 "
        plugin_string1 = "This site uses the wp-captcha plugin."
        plugin_string2 = "No plugin name in this string"
        plugin_string3 = "This site uses the Google Analytics by MonsterInsights plugin"

        plugin0_meta = Meta(key="plugins/wp-parsely", name="Parse.ly")
        plugin1_meta = Meta(key="plugins/wp-captcha", name="WP Captcha")
        self.plugin_finder.meta_list = MetaList(key="plugins", metas=[plugin0_meta, plugin1_meta,
                                                                      self.google_analytics_meta])

        plugin0_key = self.plugin_finder._get_plugin_key_from_name_in_comment(plugin_string0)
        plugin1_key = self.plugin_finder._get_plugin_key_from_name_in_comment(plugin_string1)
        plugin2_key = self.plugin_finder._get_plugin_key_from_name_in_comment(plugin_string2)
        plugin3_key = self.plugin_finder._get_plugin_key_from_name_in_comment(plugin_string3)

        self.assertEqual(plugin0_key, plugin0_meta.key)
        self.assertEqual(plugin1_key, plugin1_meta.key)
        self.assertIsNone(plugin2_key)
        self.assertEqual(plugin3_key, self.google_analytics_meta.key)

    def test_get_plugin_key_from_meta_url_in_string(self):
        plugin0_string = "This site uses the Google Analytics by MonsterInsights plugin v5.5.4 - Universal enabled - https://www.monsterinsights.com/"
        plugin1_string = "This site is optimized with the Yoast SEO plugin v4.0.2 - https://yoast.com/wordpress/plugins/seo/"
        plugin2_string = "Performance optimized by W3 Total Cache. Learn more: http://www.w3-edge.com/wordpress-plugins"
        plugin3_string = "String with a random url: https://www.google.com"

        plugin_key0 = self.plugin_finder._get_plugin_key_from_meta_url_in_string(plugin0_string)
        plugin_key1 = self.plugin_finder._get_plugin_key_from_meta_url_in_string(plugin1_string)
        plugin_key2 = self.plugin_finder._get_plugin_key_from_meta_url_in_string(plugin2_string)
        plugin_key3 = self.plugin_finder._get_plugin_key_from_meta_url_in_string(plugin3_string)

        self.assertEqual(plugin_key0, self.google_analytics_meta.key)
        self.assertEqual(plugin_key1, self.yoast_seo_meta.key)
        self.assertEqual(plugin_key2, self.total_cache_meta.key)
        self.assertIsNone(plugin_key3)

    def test_get_plugin_key_from_meta_url_in_string_return_key_with_longest_url_match(self):
        # This string has the plugin name and a part of its url:
        string = "This site is optimized with the Yoast SEO plugin v4.0.2 - https://yoast.com/wordpress/plugins/seo/"
        email_commenter_meta = Meta(key="plugins/email-commenters", name="Email Commenters",
                                    # url matches, but shorter than the other match
                                    url="http://yoast.com/wordpress/email-commenters/")
        self.plugin_finder.meta_list.metas.append(email_commenter_meta)

        plugin_key = self.plugin_finder._get_plugin_key_from_meta_url_in_string(string)

        self.assertEqual(plugin_key, self.yoast_seo_meta.key)

    def test_contains_url(self):
        string0 = "string with an url: http://www.google.com/"
        string1 = "another string with an url https://www.delve-labs.com/"
        string2 = "http://www.w3-edge.com/wordpress-plugins more characters..."
        string3 = "no url in this string..."
        string4 = "no url here too, but .com present."

        self.assertTrue(self.plugin_finder._contains_url(string0))
        self.assertTrue(self.plugin_finder._contains_url(string1))
        self.assertTrue(self.plugin_finder._contains_url(string2))
        self.assertFalse(self.plugin_finder._contains_url(string3))
        self.assertFalse(self.plugin_finder._contains_url(string4))

    def test_get_version_return_plugin_version_from_string(self):
        string0 = "This site is optimized with the Yoast SEO plugin v4.0.2 - https://yoast.com/wordpress/plugins/seo/"
        string_without_version = "The amazing plugin without version."
        string1 = "This site uses the Google Analytics by MonsterInsights plugin v5.5.4 - Universal enabled - " \
                  "https://www.monsterinsights.com/"
        string2 = "BEGIN wp-parsely Plugin Version 1.10.2"

        version0 = self.plugin_finder._get_version(string0)
        version1 = self.plugin_finder._get_version(string1)
        version2 = self.plugin_finder._get_version(string2)
        no_version = self.plugin_finder._get_version(string_without_version)

        self.assertEqual(version0, "4.0.2")
        self.assertEqual(version1, "5.5.4")
        self.assertEqual(version2, "1.10.2")
        self.assertIsNone(no_version)
