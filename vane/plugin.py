import re


plugin_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/(mu-)?plugins/[\w-]+$")
relative_plugin_url = re.compile("/wp-content/(mu-)?plugins/[\w-]+$")


class Plugin:

    def __init__(self, url):
        if not plugin_url.match(url) and not relative_plugin_url.match(url):
            raise ValueError("%s is not a valid url for a Wordpress plugin." % url)
        self.url = url

    @property
    def name(self):
        return re.search("[^/]+$", self.url).group()

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
