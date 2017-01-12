from lxml import etree
import re


plugins_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/(mu-)?plugins/")
plugin_in_comment = re.compile("(\w+\s)+plugin")
plugin_author_in_comment = re.compile("([\w]+\s)+by ([\w]+\s)+plugin")
comment_after_document = re.compile("</html>.*<!--.*-->$", re.DOTALL)


class PassivePluginsFinder:

    def __init__(self):
        self.plugins_database = None

    def set_plugins_database(self, database):
        self.plugins_database = database

    def list_plugins(self, html_page):
        plugins = self.find_plugins_in_elements(html_page)
        plugins.extend(self.find_plugins_in_comments(html_page))
        return plugins

    def find_plugins_in_elements(self, html_page):
        plugins = []
        element_tree_iterator = etree.iterparse(html_page, html=True)
        for event, element in element_tree_iterator:
            plugins.extend(self._search_in_element_attributes(element))
        return self._remove_duplicates(plugins)

    def find_plugins_in_comments(self, html_page):
        plugins = []
        element_tree_iterator = etree.iterparse(html_page, html=True, events=("comment",))
        for event, comment_element in element_tree_iterator:
            plugin_name = self._get_plugin_name_from_comment_text(comment_element.text)
            if plugin_name is not None:
                plugins.append(plugin_name)
        plugins.extend(self._check_for_comments_at_document_end(html_page))
        return self._remove_duplicates(plugins)

    def _search_in_element_attributes(self, element):
        plugins = []
        for attribute_name, attribute_value in element.items():
            if "plugin" in attribute_name:
                if self.is_plugin(attribute_value):
                    plugins.append(self.get_official_plugin_name_from_database(attribute_value))
            elif self._is_plugin_url(attribute_value):
                plugins.append(self._get_plugin_name_from_url(attribute_value))
        return plugins

    def _get_plugin_name_from_comment_text(self, comment):
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
                print(comment)
                plugin_name = self._get_plugin_name_from_comment_text(comment)
                if plugin_name is not None:
                    plugins.append(plugin_name)
        return plugins

    def is_plugin(self, plugin_name):
        return self.get_official_plugin_name_from_database(plugin_name) is not None

    def get_official_plugin_name_from_database(self, plugin_name):
        for plugin in self.plugins_database.get_plugins():
            if self.plugin_names_equal(plugin, plugin_name):
                return plugin

    def plugin_names_equal(self, name0, name1):
        return self.strip_name(name0) == self.strip_name(name1)

    def _find_plugin_name_in_string(self, string):
        stripped_string = self.strip_name(string)
        longest_match = ""
        for plugin in self.plugins_database.get_plugins():
            if self.strip_name(plugin) in stripped_string:
                if len(plugin) > len(longest_match):
                    longest_match = plugin
        return longest_match if len(longest_match) > 0 else None

    def strip_name(self, name):
        name = name.lower()
        return re.sub('\W', '', name)

    def _is_plugin_url(self, url):
        if plugins_url.search(url):
            return self._get_plugin_name_from_url(url) is not None

    def _get_plugin_name_from_url(self, url):
        plugin_name = plugins_url.sub("", url)
        plugin_name = re.match("[^/]+", plugin_name).group()
        return self.get_official_plugin_name_from_database(plugin_name)

    def _remove_duplicates(self, plugin_list):
        return list(set(plugin_list))
