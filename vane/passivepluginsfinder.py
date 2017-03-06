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
from vane.plugin import Plugin
from io import BytesIO


plugin_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/(mu-)?plugins/[^/]+")
relative_plugin_url = re.compile("/wp-content/(mu-)?plugins/[^/]+")
plugin_in_comment = re.compile("(\w+\s)+plugin")
plugin_author_in_comment = re.compile("([\w]+\s)+by ([\w]+\s)+plugin")
comment_after_document = re.compile("</html>.*<!--.*-->$", re.DOTALL)


class PassivePluginsFinder:

    def __init__(self, logger, plugins_database):
        self.plugins_database = plugins_database
        self.meta_list = None
        self.logger = logger

    def set_plugins_database(self, database):
        self.plugins_database = database

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
            if self._contains_plugin_url(attribute_value):
                yield Plugin(self._get_plugin_url_from_string(attribute_value))

    def _find_plugins_in_comments(self, hammertime_response):
        raw_html = BytesIO(hammertime_response.raw)
        element_tree_iterator = etree.iterparse(raw_html, html=True, events=("comment",))
        for event, comment_element in element_tree_iterator:
            if self._contains_plugin_url(comment_element.text):
                yield Plugin(self._get_plugin_url_from_string(comment_element.text))
            else:
                pass #plugin_name = self._find_plugin_name_in_comment(comment_element.text)
                #if plugin_name is not None:
                    #yield Plugin.from_name(plugin_name)
        yield from self._search_plugin_in_comments_outside_document(raw_html)

    def _find_plugin_name_in_comment(self, comment):
        plugin_name = self._find_existing_plugin_name_in_string(comment)  # search the string for a known plugin name.
        if plugin_name is None:
            plugin_name = self._find_possible_plugin_name_in_comment(comment)
        return plugin_name

    def _find_possible_plugin_name_in_comment(self, comment):
        comment = comment.lower()
        if plugin_in_comment.search(comment):
            if plugin_author_in_comment.search(comment):  # Ex: Google Analytics by MonsterInsights plugin
                end = re.search(" by", comment)
            else:
                end = re.search(" plugin", comment)
            comment = comment[:end.start()]
            # The plugin's name is probably in the three words before the 'plugin' word.
            beginning = re.search("((\s|^)[\w-]+){1,3}$", comment)
            possible_plugin_name = comment[beginning.start():]
            # For now, unknown plugin are not stored, only logged, so it is not returned.
            self._log_possible_plugin_name(possible_plugin_name.strip())

    def _log_possible_plugin_name(self, plugin_name):
        self.logger.add_plugin(plugin_name)

    def _search_plugin_in_comments_outside_document(self, html_page):
        with open(html_page, "r") as fp:
            page_content = fp.read()
            for comment in comment_after_document.findall(page_content):
                plugin_name = self._find_plugin_name_in_comment(comment)
                if plugin_name is not None:
                    yield Plugin.from_name(plugin_name)

    def _find_existing_plugin_in_string(self, string):
        longest_match = ""
        for plugin_key in self._find_possible_plugin_keys_in_meta(string):
            if len(plugin_key) > len(longest_match):
                longest_match = plugin_key
        if len(longest_match) > 0:
            return longest_match
        else:
            best_match = None
            for meta in self._find_possible_plugin_names_in_meta(string):
                if best_match is None:
                    best_match = meta
                elif len(meta.name) > len(best_match.name):
                    best_match = meta
            return best_match.key if best_match is not None else None

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
                if plugin_meta.name is not None and plugin_meta.name in string:
                    possible_metas.append(plugin_meta)
        return possible_metas
