from unittest import TestCase

from vane.theme import Theme


class TestTheme(TestCase):

    def test_constructor_raise_value_error_if_url_is_not_a_valid_theme_url(self):
        junk_url = "https://www.mywebsite.com/something.html"
        valid_url_with_file_at_end = "https://www.delve-labs.com/wp-content/themes/delvelabs/style.css"
        url_with_junk_at_beginning = "link to theme: https://www.delve-labs.com/wp-content/themes/delvelabs"

        with self.assertRaises(ValueError):
            Theme(junk_url)
        with self.assertRaises(ValueError):
            Theme(valid_url_with_file_at_end)
        with self.assertRaises(ValueError):
            Theme(url_with_junk_at_beginning)

    def test_constructor_accept_relative_url(self):
        relative_url = "/wp-content/themes/my-theme"

        Theme(relative_url)

    def test_name_return_name_from_theme_url(self):
        theme = Theme("https://www.delve-labs.com/wp-content/themes/delvelabs")

        self.assertEqual(theme.name, "delvelabs")

    def test_name_return_name_from_vip_theme_url(self):
        theme = Theme("https://s0.wp.com/wp-content/themes/vip/techcrunch-2013")

        self.assertEqual(theme.name, "techcrunch-2013")

    def test_name_return_name_from_relative_theme_url(self):
        theme = Theme("/wp-content/themes/my-theme")

        self.assertEqual(theme.name, "my-theme")

    def test_themes_equal_if_themes_have_same_name(self):
        theme0 = Theme("https://www.mysite.com/wp-content/themes/my-theme")
        theme1 = Theme("https://www.mysite.com/wp-content/themes/my-theme")

        self.assertEqual(theme0, theme1)

    def test_themes_equal_is_false_if_themes_have_different_name(self):
        theme0 = Theme("https://www.mysite.com/wp-content/themes/my-theme")
        theme1 = Theme("https://www.mysite.com/wp-content/themes/another-theme")

        self.assertNotEqual(theme0, theme1)
