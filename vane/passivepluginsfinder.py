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
from urllib.parse import urlparse
from difflib import SequenceMatcher


plugin_path = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/(mu-)?plugins/[^/]+")
relative_plugin_path = re.compile("/wp-content/(mu-)?plugins/[^/]+")
plugin_in_comment = re.compile("(\w+\s)+plugin")
comment_after_document = re.compile("</html>.*<!--.*-->$", re.DOTALL)
url_pattern = re.compile("https?://([\w-]+\.)+\w+/?([\w-]*/?)*")


class PassivePluginsFinder:

    def __init__(self, meta_list):
        self.meta_list = meta_list

    def set_plugins_meta_list(self, meta_list):
        self.meta_list = meta_list

    def list_plugins(self, hammertime_response):
        plugin_keys = set(self._find_plugins_in_elements(hammertime_response))

        plugins_version = {}
        for plugin_dict in self._find_plugins_in_comments(hammertime_response):
            plugin_key, version = plugin_dict.popitem()
            if plugin_key not in plugins_version:
                plugins_version[plugin_key] = version
            elif version is not None:
                plugins_version[plugin_key] = version

        for plugin_key in plugin_keys:
            if plugin_key not in plugins_version:
                plugins_version[plugin_key] = None
        return plugins_version

    def _find_plugins_in_elements(self, hammertime_response):
        raw_html = BytesIO(hammertime_response.raw)
        element_tree_iterator = etree.iterparse(raw_html, html=True)
        for event, element in element_tree_iterator:
            yield from self._search_in_element_attributes(element)

    def _search_in_element_attributes(self, element):
        for attribute_name, attribute_value in element.items():
            if self._contains_plugin_path(attribute_value):
                plugin_key = self._get_plugin_key_from_plugin_path_in_string(attribute_value)
                if plugin_key is not None:
                    yield plugin_key

    def _find_plugins_in_comments(self, hammertime_response):
        raw_html = BytesIO(hammertime_response.raw)
        element_tree_iterator = etree.iterparse(raw_html, html=True, events=("comment",))
        for event, comment_element in element_tree_iterator:
            plugin_key = self._find_plugin_in_string(comment_element.text)
            if plugin_key is not None:
                yield plugin_key
        yield from self._search_plugin_in_comments_outside_document(hammertime_response)

    def _search_plugin_in_comments_outside_document(self, hammertime_response):
        page_content = hammertime_response.raw.decode("utf-8")
        for comment in comment_after_document.findall(page_content):
            plugin_key = self._find_plugin_in_string(comment)
            if plugin_key is not None:
                yield plugin_key

    def _find_plugin_in_string(self, string):
        if self._contains_plugin_path(string):
            plugin_key = self._get_plugin_key_from_plugin_path_in_string(string)
            if plugin_key is not None:
                version = self._get_version(string)
                return {plugin_key: version}
        if self._contains_url(string):
            plugin_key = self._get_plugin_key_from_meta_url_in_string(string)
            if plugin_key is not None:
                version = self._get_version(string)
                return {plugin_key: version}
        plugin_key = self._get_plugin_key_from_name_in_string(string)
        if plugin_key is not None:
            return {plugin_key: self._get_version(string)}
        return None

    def _get_plugin_key_from_plugin_path_in_string(self, string):
        path = self._get_plugin_path_from_string(string)
        possible_plugin_key = self._get_plugin_key_from_plugin_path(path)
        return possible_plugin_key if self._plugin_exists(possible_plugin_key) else None

    def _contains_plugin_path(self, url):
        return plugin_path.search(url) is not None or relative_plugin_path.search(url) is not None

    def _get_plugin_path_from_string(self, string):
        if plugin_path.search(string):
            return plugin_path.search(string).group()
        else:
            return relative_plugin_path.search(string).group()

    def _get_plugin_key_from_plugin_path(self, url):
        return re.search("plugins/.+$", url).group()

    def _get_plugin_key_from_name_in_string(self, string):
        string = string.lower()
        if plugin_in_comment.search(string):
            end = re.search(" plugin", string)
            string = string[:end.start()]
            words = string.split(" ")
            for word in words:
                if "-" in word:  # may be the key of the plugin.
                    possible_plugin_key = "plugins/" + word
                    if self._plugin_exists(possible_plugin_key):
                        return possible_plugin_key
            plugin_key = self._find_longest_match_for_plugin_name_in_string(string)
            if plugin_key is not None:
                return plugin_key
        return None

    def _find_longest_match_for_plugin_name_in_string(self, string):
        possible_metas = self._find_all_possible_matches_for_plugin_name_in_string(string)
        if len(possible_metas) > 1:
            match = max(possible_metas, key=lambda meta_match: len(meta_match.name))
            return match.key
        elif len(possible_metas) == 1:
            return possible_metas[0].key
        return None

    def _find_all_possible_matches_for_plugin_name_in_string(self, string):
        possible_matching_metas = []
        words = string.lower().split(" ")
        for plugin_meta in self.meta_list.metas:
            if plugin_meta.name is not None:
                plugin_name = plugin_meta.name.lower().split(" ")
                if get_size_of_matching_sequence(plugin_name, words) == len(plugin_name):
                    possible_matching_metas.append(plugin_meta)
        return possible_matching_metas

    def _get_plugin_key_from_meta_url_in_string(self, string):
        url = url_pattern.search(string).group()
        parsed_url = urlparse(url)
        possible_metas = []
        for plugin_meta in self.meta_list.metas:
            if plugin_meta.url is not None:
                meta_url = urlparse(plugin_meta.url)
                if parsed_url.netloc == meta_url.netloc:
                    possible_metas.append(plugin_meta)
        if len(possible_metas) > 1 and len(parsed_url.path) > 0:
            return self._get_best_meta_url_match_based_on_url_path(possible_metas, parsed_url)
        return possible_metas[0].key if len(possible_metas) == 1 else None

    def _get_best_meta_url_match_based_on_url_path(self, possible_metas, parsed_url):
        best_match = None
        best_match_size = 0
        for meta in possible_metas:
            meta_url = urlparse(meta.url)
            if len(meta_url.path) > 0:
                match_size = get_size_of_matching_sequence(meta_url.path, parsed_url.path)
                if match_size > best_match_size:
                    best_match = meta.key
                    best_match_size = match_size
        return best_match

    def _contains_url(self, string):
        return url_pattern.search(string) is not None

    def _get_version(self, string):
        match = re.search("[Vv](ersion)?[\s]*\d+\.\d+(\.\d+)?", string)
        if match is not None:
            version = match.group()
            version = re.sub("^\D+", "", version)
            return version
        return None

    def _plugin_exists(self, plugin_key):
        return self.meta_list.get_meta(plugin_key) is not None


def get_size_of_matching_sequence(sequence, _sequence):
    sequence_matcher = SequenceMatcher(a=sequence, b=_sequence)
    match = sequence_matcher.find_longest_match(0, len(sequence), 0, len(_sequence))
    return match.size
