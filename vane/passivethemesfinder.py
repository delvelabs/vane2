import re
from lxml import etree

theme_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/themes/(vip/)?")


class PassiveThemesFinder:

    def __init__(self):
        self.themes_database = None

    def set_plugins_database(self, database):
        self.themes_database = database

    def list_themes(self, html_page):
        element_tree_iterator = etree.iterparse(html_page, html=True, events=("comment",))
        themes = []
        for event, comment_element in element_tree_iterator:
            theme_name = self._find_theme_url_in_comment(comment_element.text)
            if theme_name is not None:
                themes.append(theme_name)
        return themes

    def _find_theme_url_in_comment(self, comment):
        if self._is_theme_url(comment):  # TODO change if _is_theme_url change
            match = theme_url.search(comment)
            url = comment[match.start():]
            return self._get_theme_name_from_url(url)

    # TODO rename to 'contains_theme_url' or change search for match?
    def _is_theme_url(self, url):
        if theme_url.search(url):
            return True
        return False

    def _get_theme_name_from_url(self, url):
        theme_name = theme_url.sub("", url)
        theme_name = re.match("[^/]+", theme_name).group()
        return self._get_official_theme_name_from_database(theme_name)

    def _theme_names_equal(self, name0, name1):
        return self._strip_name(name0) == self._strip_name(name1)

    def _strip_name(self, name):
        name = name.lower()
        return re.sub('\W', '', name)

    def _get_official_theme_name_from_database(self, theme_name):
        for theme in self.themes_database.get_themes():
            if self._theme_names_equal(theme, theme_name):
                return theme
