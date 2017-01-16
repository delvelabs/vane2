import re
from lxml import etree

from vane.theme import Theme

theme_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/themes/(vip/)?[^/]+")
relative_theme_url = re.compile("/wp-content/themes/(vip/)?[^/]+")


class PassiveThemesFinder:

    def list_themes(self, html_page):
        themes = set(self._find_themes_in_elements(html_page))
        return themes | set(self._find_themes_in_comments(html_page))

    def _find_themes_in_comments(self, html_page):
        element_tree_iterator = etree.iterparse(html_page, html=True, events=("comment",))
        for event, comment_element in element_tree_iterator:
            if self._contains_theme_url(comment_element.text):
                yield Theme(self._get_theme_url_from_string(comment_element.text))

    def _find_themes_in_elements(self, html_page):
        element_tree_iterator = etree.iterparse(html_page, html=True)
        for event, element in element_tree_iterator:
            yield from self._find_theme_in_element_attributes(element)

    def _find_theme_in_element_attributes(self, element):
        for attribute_name, attribute_value in element.items():
            if self._contains_theme_url(attribute_value):
                yield Theme(self._get_theme_url_from_string(attribute_value))

    def _contains_theme_url(self, string):
        return theme_url.search(string) is not None or relative_theme_url.search(string) is not None

    def _get_theme_url_from_string(self, string):
        if theme_url.search(string):
            return theme_url.search(string).group()
        else:
            return relative_theme_url.search(string).group()
