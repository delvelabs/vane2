from lxml import etree
import re
from vane.plugin import Plugin


plugin_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/(mu-)?plugins/[^/]+")
relative_plugin_url = re.compile("/wp-content/(mu-)?plugins/[^/]+")
plugin_in_comment = re.compile("(\w+\s)+plugin")
plugin_author_in_comment = re.compile("([\w]+\s)+by ([\w]+\s)+plugin")
comment_after_document = re.compile("</html>.*<!--.*-->$", re.DOTALL)


class PassivePluginsFinder:

    def __init__(self, logger, plugins_database):
        self.plugins_database = plugins_database
        self.logger = logger

    def set_plugins_database(self, database):
        self.plugins_database = database

    def set_logger(self, logger):
        self.logger = logger

    def list_plugins(self, html_page):
        plugins = set(self._find_plugins_in_elements(html_page))
        return plugins | set(self._find_plugins_in_comments(html_page))

    def _find_plugins_in_elements(self, html_page):
        element_tree_iterator = etree.iterparse(html_page, html=True)
        for event, element in element_tree_iterator:
            yield from self._search_in_element_attributes(element)

    def _search_in_element_attributes(self, element):
        for attribute_name, attribute_value in element.items():
            if self._contains_plugin_url(attribute_value):
                yield Plugin(self._get_plugin_url_from_string(attribute_value))

    def _find_plugins_in_comments(self, html_page):
        element_tree_iterator = etree.iterparse(html_page, html=True, events=("comment",))
        for event, comment_element in element_tree_iterator:
            if self._contains_plugin_url(comment_element.text):
                yield Plugin(self._get_plugin_url_from_string(comment_element.text))
            else:
                plugin_name = self._find_plugin_name_in_comment(comment_element.text)
                if plugin_name is not None:
                    yield Plugin.from_name(plugin_name)
        yield from self._search_plugin_in_comments_outside_document(html_page)

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

    def _find_existing_plugin_name_in_string(self, string):
        stripped_string = self._strip_name(string)
        longest_match = ""
        for plugin in self.plugins_database.get_plugin_names():
            if self._strip_name(plugin) in stripped_string:
                if len(plugin) > len(longest_match):
                    longest_match = plugin
        return longest_match if len(longest_match) > 0 else None

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
