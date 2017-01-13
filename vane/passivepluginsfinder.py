from lxml import etree
import re
from vane.plugin import Plugin


plugin_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/(mu-)?plugins/")
relative_plugin_url = re.compile("/wp-content/(mu-)?plugins/")
plugin_in_comment = re.compile("(\w+\s)+plugin")
plugin_author_in_comment = re.compile("([\w]+\s)+by ([\w]+\s)+plugin")
comment_after_document = re.compile("</html>.*<!--.*-->$", re.DOTALL)


class PassivePluginsFinder:

    def __init__(self):
        self.plugins_database = None

    def set_plugins_database(self, database):
        self.plugins_database = database

    def list_plugins(self, html_page):
        plugins = self._find_plugins_in_elements(html_page)
        plugins.extend(self._find_plugins_in_comments(html_page))
        return self._remove_duplicates(plugins)

    def _find_plugins_in_elements(self, html_page):
        plugins = []
        element_tree_iterator = etree.iterparse(html_page, html=True)
        for event, element in element_tree_iterator:
            plugins.extend(self._search_in_element_attributes(element))
        return self._remove_duplicates(plugins)

    def _search_in_element_attributes(self, element):
        plugins = []
        for attribute_name, attribute_value in element.items():
            if self._contains_plugin_url(attribute_value):
                plugin = Plugin(self._get_plugin_url_from_string(attribute_value))
                plugins.append(plugin)
        return plugins

    def _find_plugins_in_comments(self, html_page):
        plugins = []
        element_tree_iterator = etree.iterparse(html_page, html=True, events=("comment",))
        for event, comment_element in element_tree_iterator:
            if self._contains_plugin_url(comment_element.text):
                plugin = Plugin(self._get_plugin_url_from_string(comment_element.text))
                plugins.append(plugin)
            else:
                plugin_name = self._find_existing_plugin_name_in_comment(comment_element.text)
                if plugin_name is not None:
                    plugins.append(Plugin.from_name(plugin_name))
        plugins.extend(self._check_for_comments_at_document_end(html_page))
        return self._remove_duplicates(plugins)

    def _find_existing_plugin_name_in_comment(self, comment):
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
            return self._find_plugin_name_in_string(possible_plugin_name)
        # if no 'plugin' keyword found in comment, just try to find a plugin name in the comment.
        return self._find_plugin_name_in_string(comment)

    def _check_for_comments_at_document_end(self, html_page):
        plugins = []
        with open(html_page, "r") as fp:
            page_content = fp.read()
            for comment in comment_after_document.findall(page_content):
                plugin_name = self._find_existing_plugin_name_in_comment(comment)
                if plugin_name is not None:
                    plugin = Plugin.from_name(plugin_name)
                    plugins.append(plugin)
        return plugins

    def _is_plugin(self, plugin_name):
        return self._get_plugin_name_from_database(plugin_name) is not None

    def _get_plugin_name_from_database(self, plugin_name):
        return plugin_name

    def _plugin_names_equal(self, name0, name1):
        return self._strip_name(name0) == self._strip_name(name1)

    def _find_plugin_name_in_string(self, string):
        stripped_string = self._strip_name(string)
        longest_match = ""
        for plugin in self.plugins_database.get_plugins():
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
        url_match = plugin_url.search(string)
        url = string[url_match.start():]
        plugin_url_prefix_end = plugin_url.match(url).end()
        url_end = re.search("[^/]+", url[plugin_url_prefix_end:]).end()
        return url[:plugin_url_prefix_end + url_end]

    def _remove_duplicates(self, plugin_list):
        return list(set(plugin_list))
