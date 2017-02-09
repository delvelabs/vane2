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
