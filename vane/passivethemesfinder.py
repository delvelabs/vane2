import re
from lxml import etree

from vane.theme import Theme

theme_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/themes/(vip/)?")


class PassiveThemesFinder:

    def list_themes(self, html_page):
        themes = self._find_themes_in_elements(html_page)
        themes.extend(self._find_themes_in_comments(html_page))
        return self._remove_duplicates(themes)

    def _find_themes_in_comments(self, html_page):
        element_tree_iterator = etree.iterparse(html_page, html=True, events=("comment",))
        themes = []
        for event, comment_element in element_tree_iterator:
            if self._contains_theme_url(comment_element.text):
                url = self._get_theme_url_from_string(comment_element.text)
                themes.append(Theme(url))
        return themes

    def _find_themes_in_elements(self, html_page):
        themes = []
        element_tree_iterator = etree.iterparse(html_page, html=True)
        for event, element in element_tree_iterator:
            themes.extend(self._find_theme_in_element_attributes(element))
        return themes

    def _find_theme_in_element_attributes(self, element):
        themes = []
        for attribute_name, attribute_value in element.items():
            if self._contains_theme_url(attribute_value):
                url = self._get_theme_url_from_string(attribute_value)
                themes.append(Theme(url))
        return themes

    def _contains_theme_url(self, string):
        return theme_url.search(string) is not None

    def _get_theme_url_from_string(self, string):
        url_match = theme_url.search(string)
        url = string[url_match.start():]
        theme_url_prefix_end = theme_url.match(url).end()
        url_end = re.search("[^/]+", url[theme_url_prefix_end:]).end()
        return url[:theme_url_prefix_end + url_end]

    def _remove_duplicates(self, theme_list):
        return list(set(theme_list))
