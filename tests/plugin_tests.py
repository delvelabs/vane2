from unittest import TestCase

from vane.plugin import Plugin


class TestPlugin(TestCase):

    def test_constructor_raise_value_error_if_plugin_url_not_valid_plugin_url(self):
        junk_url = "https://www.mywebsite.com/something.html"
        valid_url_with_file_at_end = "https://www.delve-labs.com/wp-content/plugins/my-plugin/file.php"
        url_with_junk_at_beginning = "link to plugin: https://www.delve-labs.com/wp-content/plugins/my-plugin"

        with self.assertRaises(ValueError):
            Plugin(junk_url)
        with self.assertRaises(ValueError):
            Plugin(valid_url_with_file_at_end)
        with self.assertRaises(ValueError):
            Plugin(url_with_junk_at_beginning)

    def test_name_return_name_of_plugin_from_plugin_url(self):
        url = "http://static.blog.playstation.com/wp-content/plugins/wp-polls"
        plugin = Plugin(url)

        self.assertEqual(plugin.name, "wp-polls")

    def test_name_return_name_of_plugin_from_mu_plugin_url(self):
        url = "https://s1.wp.com/wp-content/mu-plugins/gravatar-hovercards"
        plugin = Plugin(url)

        self.assertEqual(plugin.name, "gravatar-hovercards")

    def test_name_return_name_of_plugin_from_relative_plugin_url(self):
        url = "/wp-content/plugins/ie-sitemode"
        plugin = Plugin(url)

        self.assertEqual(plugin.name, "ie-sitemode")
        
    def test_plugin_equal_if_plugins_have_same_name(self):
        plugin0 = Plugin("https://www.mysite.com/wp-content/plugins/my-plugin")
        plugin1 = Plugin("https://www.mysite.com/wp-content/plugins/my-plugin")

        self.assertEqual(plugin0, plugin1)

    def test_plugin_equal_is_false_if_plugins_have_different_name(self):
        plugin0 = Plugin("https://www.mysite.com/wp-content/plugins/my-plugin")
        plugin1 = Plugin("https://www.mysite.com/wp-content/plugins/another-plugin")

        self.assertNotEqual(plugin0, plugin1)

    def test_from_name_creates_a_relative_plugin_url_with_the_name(self):
        plugin = Plugin.from_name("my-plugin")

        self.assertEqual(plugin.url, "/wp-content/plugins/my-plugin")
