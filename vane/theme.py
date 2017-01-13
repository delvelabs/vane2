import re

theme_url_without_theme_name = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/themes/(vip/)?")
theme_url = re.compile("(https?:)?//([\w%-]+(\.|/))+wp-content/themes/(vip/)?[\w-]+$")


class Theme:

    def __init__(self, url):
        if not theme_url.match(url):
            raise ValueError("%s is not a valid url for a Wordpress theme" % url)
        self.url = url

    @property
    def name(self):
        return theme_url_without_theme_name.sub("", self.url)

    def __eq__(self, other):
        return self.name == other.name

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.name)
