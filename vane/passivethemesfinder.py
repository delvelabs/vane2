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
