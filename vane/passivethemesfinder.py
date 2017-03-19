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
from io import BytesIO

theme_path = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/themes/(vip/)?[^/]+")
relative_theme_path = re.compile("/wp-content/themes/(vip/)?[^/]+")


class PassiveThemesFinder:

    def __init__(self, meta_list):
        self.meta_list = meta_list

    def list_themes(self, hammertime_response):
        themes = set(self._find_themes_in_elements(hammertime_response))
        return themes | set(self._find_themes_in_comments(hammertime_response))

    def _find_themes_in_comments(self, hammertime_response):
        raw_html = BytesIO(hammertime_response.raw)
        element_tree_iterator = etree.iterparse(raw_html, html=True, events=("comment",))
        for event, comment_element in element_tree_iterator:
            theme_key = self._find_theme_in_string(comment_element.text)
            if theme_key is not None:
                yield theme_key

    def _find_themes_in_elements(self, hammertime_response):
        raw_html = BytesIO(hammertime_response.raw)
        element_tree_iterator = etree.iterparse(raw_html, html=True)
        for event, element in element_tree_iterator:
            yield from self._find_theme_in_element_attributes(element)

    def _find_theme_in_element_attributes(self, element):
        for attribute_name, attribute_value in element.items():
            theme_key = self._find_theme_in_string(attribute_value)
            if theme_key is not None:
                yield theme_key

    def _find_theme_in_string(self, string):
        if self._contains_theme_path(string):
            theme_path = self._get_theme_path_from_string(string)
            theme_key = self._get_theme_key_from_path(theme_path)
            if self._theme_exists(theme_key):
                return theme_key
        return None

    def _contains_theme_path(self, string):
        return theme_path.search(string) is not None or relative_theme_path.search(string) is not None

    def _get_theme_path_from_string(self, string):
        if theme_path.search(string):
            return theme_path.search(string).group()
        else:
            return relative_theme_path.search(string).group()

    def _get_theme_key_from_path(self, path):
        return re.search("themes/.+$", path).group()

    def _theme_exists(self, theme_key):
        return self.meta_list.get_meta(theme_key) is not None
