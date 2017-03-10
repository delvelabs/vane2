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


plugin_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/(mu-)?plugins/[^/]+")
relative_plugin_url = re.compile("/wp-content/(mu-)?plugins/[^/]+")
plugin_in_comment = re.compile("(\w+\s)+plugin")
comment_after_document = re.compile("</html>.*<!--.*-->$", re.DOTALL)
url_pattern = re.compile("https?://([\w-]+\.)+\w+/?([\w-]*/?)*")


class PassivePluginsFinder:

    def __init__(self, meta_list):
        self.meta_list = meta_list

    def set_plugins_meta_list(self, meta_list):
        self.meta_list = meta_list

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
            if self._contains_plugin_url(attribute_value):
                plugin_url = self._get_plugin_url_from_string(attribute_value)
                plugin_key = self._get_plugin_key_from_plugin_url(plugin_url)
                if self.meta_list.get_meta(plugin_key) is not None:
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
        if self._contains_plugin_url(string):
            plugin_url = self._get_plugin_url_from_string(string)
            possible_plugin_key = self._get_plugin_key_from_plugin_url(plugin_url)
            confirmed_plugin_key = self._find_longest_plugin_key_match_in_meta_for_string(possible_plugin_key)
            if confirmed_plugin_key is not None:
                return confirmed_plugin_key
        if self._contains_url(string):
            plugin_key = self._get_plugin_key_from_meta_url_in_string(string)
            if plugin_key is not None:
                return plugin_key
        return self._get_plugin_key_from_name_in_comment(string)

    def _get_plugin_key_from_name_in_comment(self, string):
        string = string.lower()
        if plugin_in_comment.search(string):
            end = re.search(" plugin", string)
            string = string[:end.start()]
            words = string.split(" ")
            for word in words:
                if "-" in word:
                    plugin_key = self._find_longest_plugin_key_match_in_meta_for_string(word)
                    if plugin_key is not None:
                        return plugin_key
            plugin_key = self._find_plugin_with_longest_name_match_in_string(string)
            if plugin_key is not None:
                return plugin_key
        return None

    def _contains_plugin_url(self, url):
        return plugin_url.search(url) is not None or relative_plugin_url.search(url) is not None

    def _get_plugin_url_from_string(self, string):
        if plugin_url.search(string):
            return plugin_url.search(string).group()
        else:
            return relative_plugin_url.search(string).group()

    def _get_plugin_key_from_plugin_url(self, url):
        return re.search("plugins/.+$", url).group()

    def _find_longest_plugin_key_match_in_meta_for_string(self, string):
        possible_keys = self._find_possible_plugin_keys_in_meta(string)
        if len(possible_keys) > 0:
            return max(possible_keys, key=len)
        return None

    def _find_possible_plugin_keys_in_meta(self, string):
        possible_keys = []
        if self.meta_list is not None:
            for plugin_meta in self.meta_list.metas:
                if plugin_meta.key[len("plugins/"):] in string:
                    possible_keys.append(plugin_meta.key)
        return possible_keys

    def _find_plugin_with_longest_name_match_in_string(self, string):
        possible_metas = self._find_possible_plugin_names_matches_in_meta(string)
        if len(possible_metas) > 1:
            match = max(possible_metas, key=lambda meta_match: meta_match["match_size"])
            return match["meta"].key
        elif len(possible_metas) == 1:
            return possible_metas[0]["meta"].key
        return None

    def _find_possible_plugin_names_matches_in_meta(self, string):
        possible_matching_metas = []
        if self.meta_list is not None:
            words = string.lower().split(" ")
            for plugin_meta in self.meta_list.metas:
                if plugin_meta.name is not None:
                    _words = plugin_meta.name.lower().split(" ")
                    match_size = get_size_of_matching_sequence(words, _words)
                    if match_size >= len(_words):  # Prevent short plugins names to match a part of a longer plugin name.
                        possible_matching_metas.append({"meta": plugin_meta, "match_size": match_size})
        return possible_matching_metas

    def _get_plugin_key_from_meta_url_in_string(self, string):
        url = url_pattern.search(string).group()
        parsed_url = urlparse(url)
        possible_metas = []
        if self.meta_list is not None:
            for plugin_meta in self.meta_list.metas:
                if plugin_meta.url is not None:
                    meta_url = urlparse(plugin_meta.url)
                    if parsed_url.netloc == meta_url.netloc:
                        possible_metas.append(plugin_meta)
        return self._get_best_meta_url_match_based_on_url_path(possible_metas, parsed_url)

    def _get_best_meta_url_match_based_on_url_path(self, possible_metas, parsed_url):
        if len(possible_metas) > 1 and parsed_url.path != "":
            matches_length = {}
            for meta in possible_metas:
                meta_url = urlparse(meta.url)
                if meta_url.path != "":
                    match_size = get_size_of_matching_sequence(meta_url.path, parsed_url.path)
                    if match_size > 0:
                        matches_length[meta.key] = match_size
            if len(matches_length) > 1:
                return max(matches_length.items(), key=lambda item: item[1])[0]
            elif len(matches_length) == 1:
                return matches_length.keys()[0]
            else:
                return None
        elif len(possible_metas) == 1:
            return possible_metas[0].key
        else:
            return None

    def _contains_url(self, string):
        return url_pattern.search(string) is not None


def get_size_of_matching_sequence(sequence, _sequence):
    sequence_matcher = SequenceMatcher(a=sequence, b=_sequence)
    match = sequence_matcher.find_longest_match(0, len(sequence), 0, len(_sequence))
    return match.size
