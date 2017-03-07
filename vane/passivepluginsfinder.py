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

from lxml import etree
import re
from io import BytesIO


plugin_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/(mu-)?plugins/[^/]+")
relative_plugin_url = re.compile("/wp-content/(mu-)?plugins/[^/]+")
plugin_in_comment = re.compile("(\w+\s)+plugin")
plugin_author_in_comment = re.compile("([\w]+\s)+by ([\w]+\s)+plugin")
comment_after_document = re.compile("</html>.*<!--.*-->$", re.DOTALL)


class PassivePluginsFinder:

    def __init__(self, meta_list):
        self.meta_list = meta_list

    def set_plugins_meta_list(self, meta_list):
        self.meta_list = meta_list

    def set_logger(self, logger):
        self.logger = logger

    def list_plugins(self, hammertime_response):
        plugins = set(self._find_plugins_in_elements(hammertime_response))
        return plugins | set(self._find_plugins_in_comments(hammertime_response))

    def _find_plugins_in_elements(self, hammertime_response):
        raw_html = BytesIO(hammertime_response.raw)
        element_tree_iterator = etree.iterparse(raw_html, html=True)
        for event, element in element_tree_iterator:
            yield from self._search_in_element_attributes(element)

    def _search_in_element_attributes(self, element):
        for attribute_name, attribute_value in element.items():
            plugin_key = self._find_existing_plugin_in_string(attribute_value)
            if plugin_key is not None:
                yield plugin_key

    def _find_plugins_in_comments(self, hammertime_response):
        raw_html = BytesIO(hammertime_response.raw)
        element_tree_iterator = etree.iterparse(raw_html, html=True, events=("comment",))
        for event, comment_element in element_tree_iterator:
            plugin_key = self._find_existing_plugin_in_string(comment_element.text)
            if plugin_key is not None:
                yield plugin_key
        yield from self._search_plugin_in_comments_outside_document(hammertime_response)

    def _search_plugin_in_comments_outside_document(self, hammertime_response):
        page_content = hammertime_response.raw.decode("utf-8")
        for comment in comment_after_document.findall(page_content):
            plugin_key = self._find_existing_plugin_in_string(comment)
            if plugin_key is not None:
                yield plugin_key

    def _find_existing_plugin_in_string(self, string):
        def get_longest_match(matches, key=len):
            return max(matches, key=key)
        if self._contains_plugin_url(string):
            _string = self._get_plugin_key_from_plugin_url(self._get_plugin_url_from_string(string))
        else:
            _string = string.lower()
        possible_keys = self._find_possible_plugin_keys_in_meta(_string)
        if len(possible_keys) > 0:
            return get_longest_match(possible_keys)
        else:
            possible_metas = self._find_possible_plugin_names_in_meta(_string)
            if len(possible_metas) > 0:
                return get_longest_match(possible_metas, key=lambda meta: len(meta.name)).key
        return None

    def _strip_name(self, name):
        name = name.lower()
        return re.sub('\W', '', name)

    def _contains_plugin_url(self, url):
        return plugin_url.search(url) is not None or relative_plugin_url.search(url) is not None

    def _get_plugin_url_from_string(self, string):
        if plugin_url.search(string):
            return plugin_url.search(string).group()
        else:
            return relative_plugin_url.search(string).group()

    def _get_plugin_key_from_plugin_url(self, url):
        return re.search("plugins/.+$", url).group()

    def _find_possible_plugin_keys_in_meta(self, string):
        possible_keys = []
        if self.meta_list is not None:
            for plugin_meta in self.meta_list.metas:
                if plugin_meta.key[len("plugins/"):] in string:
                    possible_keys.append(plugin_meta.key)
        return possible_keys

    def _find_possible_plugin_names_in_meta(self, string):
        possible_metas = []
        if self.meta_list is not None:
            for plugin_meta in self.meta_list.metas:
                if plugin_meta.name is not None and plugin_meta.name.lower() in string:
                    possible_metas.append(plugin_meta)
        return possible_metas
