import re


plugin_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/(mu-)?plugins/[\w-]+$")
relative_plugin_url = re.compile("/wp-content/(mu-)?plugins/[\w-]+$")
plugin_url_without_plugin_name = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/(mu-)?plugins/")
relative_plugin_url_without_plugin_name = re.compile("/wp-content/(mu-)?plugins/")


class Plugin:

    def __init__(self, url):
        if not plugin_url.match(url) and not relative_plugin_url.match(url):
            raise ValueError("%s is not a valid url for a Wordpress plugin." % url)
        self.url = url

    @property
    def name(self):
        if self._is_url_relative():
            return relative_plugin_url_without_plugin_name.sub("", self.url)
        return plugin_url_without_plugin_name.sub("", self.url)

    def _is_url_relative(self):
        return relative_plugin_url.match(self.url) is not None

    def __eq__(self, other):
        return self.name == other.name

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.name)

    @staticmethod
    def from_name(name):
        # TODO check if adding a name attribute in plugin class is better.
        return Plugin("/wp-content/plugins/%s" % name)
