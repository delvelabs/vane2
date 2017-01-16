import re


theme_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/themes/(vip/)?[\w-]+$")
relative_theme_url = re.compile("/wp-content/themes/(vip/)?[\w-]+$")


class Theme:

    def __init__(self, url):
        if not theme_url.match(url) and not relative_theme_url.match(url):
            raise ValueError("%s is not a valid url for a Wordpress theme" % url)
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
