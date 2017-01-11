from lxml import etree
import re


plugins_url = re.compile("https?://([^.]+(\.|/))+wp-content/plugins/")
plugin_in_comment = re.compile("(\w+\s)+plugin")
plugin_author_in_comment = re.compile("([\w]+\s)+by ([\w]+\s)+plugin")


class PassivePluginsFinder:

    def __init__(self):
        self.plugins_database = None

    def set_plugins_database(self, database):
        self.plugins_database = database

    def list_plugins(self, html_page):
        plugins = []
        html_tree_iterator = etree.iterparse(html_page, html=True)
        plugins.extend(self._search_elements(html_tree_iterator))
        return plugins

    def _search_elements(self, html_tree_iterator):
        plugins = []
        for action, element in html_tree_iterator:
            plugins.extend(self._search_in_element_attributes(element))
        return plugins

    def _search_in_element_attributes(self, element):
        plugins = []
        for attribute_name, attribute_value in element.items():
            if "plugin" in attribute_name:
                if self.is_plugin(attribute_value):
                    plugins.append(self.get_official_plugin_name(attribute_value))
            elif self._is_plugin_url(attribute_value):
                plugins.append(self._get_plugin_name_from_plugins_url(attribute_value))
        return plugins

    def find_plugin_in_comment(self, comment):
        comment = comment.lower()
        if plugin_in_comment.search(comment):
            if plugin_author_in_comment.search(comment):
                end = re.search(" by", comment)
            else:
                end = re.search(" plugin", comment)
            comment = comment[:end.start()]
            beginning = re.search("((\s|^)[\w-]+){1,3}$", comment)  # The plugin's name is probably in the three words before the 'plugin' word.
            plugin_name = comment[beginning.start():]
            if re.search("the ", plugin_name):  # If there is a 'the' in the name, remove it.
                plugin_name = plugin_name[re.search("the ", plugin_name).end():]
            official_plugin_name = self._contains_plugin_name(plugin_name)
            if official_plugin_name is not None:
                return official_plugin_name
            else:
                return plugin_name.strip()
        return self._contains_plugin_name(comment)

    def is_plugin(self, plugin_name):
        for plugin in self.plugins_database.get_plugins():
            if self.plugin_names_equal(plugin, plugin_name):
                return True
        return False

    def get_official_plugin_name(self, plugin_name):
        for plugin in self.plugins_database.get_plugins():
            if self.plugin_names_equal(plugin, plugin_name):
                return plugin

    def plugin_names_equal(self, name0, name1):
        return self._remove_hyphens(self._normalize_plugin_names(name0)) == \
               self._remove_hyphens(self._normalize_plugin_names(name1))

    def _contains_plugin_name(self, string):
        stripped_string = re.sub('\W', '', string)
        for plugin in self.plugins_database.get_plugins():
            if self._remove_hyphens(plugin) in stripped_string:
                return plugin

    def _remove_hyphens(self, name):
        return re.sub("-", "", name)

    def _normalize_plugin_names(self, name):
        normalized_name = name.lower()
        return re.sub(" ", "-", normalized_name)

    def _is_plugin_url(self, url):
        return plugins_url.search(url)

    def _get_plugin_name_from_plugins_url(self, url):
        plugin_name = plugins_url.sub("", url)
        plugin_name = re.match("[^/]+", plugin_name).group(0)
        return plugin_name

