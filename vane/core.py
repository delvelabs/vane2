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

from hammertime import HammerTime
from hammertime.rules import IgnoreLargeBody, RejectStatusCode
from .versionidentification import VersionIdentification
from .hash import HashResponse
from .activecomponentfinder import ActiveComponentFinder
from .retryonerrors import RetryOnErrors

import json

from os.path import join, dirname


class Vane:

    def __init__(self):
        self.hammertime = HammerTime(retry_count=3)
        self.config_hammertime()
        self.database = None
        self.output_manager = OutputManager()

    def config_hammertime(self):
        self.hammertime.heuristics.add_multiple([RejectStatusCode(range(400, 500)), HashResponse(), IgnoreLargeBody(),
                                                 RetryOnErrors(range(500, 600))])

    async def scan_target(self, url, popular, vulnerable):
        self._load_database()
        self.output_manager.log_message("scanning %s" % url)

        await self.identify_target_version(url)
        await self.active_plugin_enumeration(url, popular, vulnerable)
        await self.active_theme_enumeration(url, popular, vulnerable)

        await self.hammertime.close()

        self.output_manager.log_message("scan done")

    async def identify_target_version(self, url):
        self.output_manager.log_message("Identifying Wordpress version for %s" % url)

        version_identifier = VersionIdentification(self.hammertime)
        # TODO put in _load_database?
        version_identifier.load_files_signatures(join(dirname(__file__), "wordpress_vane2_versions.json"))

        version = await version_identifier.identify_version(url)
        self.output_manager.set_wordpress_version(version)

    async def active_plugin_enumeration(self, url, popular, vulnerable):
        self._log_active_enumeration_type("plugins", popular, vulnerable)

        component_finder = ActiveComponentFinder(self.hammertime, url)
        # TODO use user input for path?
        errors = component_finder.load_components_identification_file(dirname(__file__), "plugins", popular, vulnerable)

        for error in errors:
            self.output_manager.log_message(repr(error))

        async for plugin in component_finder.enumerate_found():
            self.output_manager.add_plugin(plugin['key'])

    async def active_theme_enumeration(self, url, popular, vulnerable):
        self._log_active_enumeration_type("themes", popular, vulnerable)

        component_finder = ActiveComponentFinder(self.hammertime, url)
        # TODO use user input for path?
        errors = component_finder.load_components_identification_file(dirname(__file__), "themes", popular, vulnerable)

        for error in errors:
            self.output_manager.log_message(repr(error))

        async for theme in component_finder.enumerate_found():
            self.output_manager.add_theme(theme['key'])

    def _log_active_enumeration_type(self, key, popular, vulnerable):
        if popular and vulnerable:
            message = "popular and vulnerable"
        elif popular:
            message = "popular"
        elif vulnerable:
            message = "vulnerable"
        else:
            message = "all"
        self.output_manager.log_message("Active enumeration of {0} {1}.".format(message, key))

    # TODO
    def _load_database(self):
        # load database
        if self.database is not None:
            self.output_manager.set_vuln_database_version(self.database.get_version())

    def perform_action(self, action="scan", url=None, database_path=None, popular=False, vulnerable=False):
        if action == "scan":
            if url is None:
                raise ValueError("Target url required.")
            self.hammertime.loop.run_until_complete(self.scan_target(url, popular=popular, vulnerable=vulnerable))
        elif action == "import_data":
            pass
        self.output_manager.flush()


class OutputManager:

    def __init__(self, output_format="json"):
        self.output_format = output_format
        self.data = {}

    def log_message(self, message):
        self._add_data("general_log", message)

    def _format(self, data):
        if self.output_format == "json":
            return json.dumps(data, indent=4)

    def set_wordpress_version(self, version):
        self.data["wordpress_version"] = version

    def set_vuln_database_version(self, version):
        self.data["vuln_database_version"] = version

    def add_plugin(self, plugin):
        self._add_data("plugins", plugin)

    def add_theme(self, theme):
        self._add_data("themes", theme)

    def add_vulnerability(self, vulnerability):
        self._add_data("vulnerabilities", vulnerability)

    def flush(self):
        print(self._format(self.data))

    def _add_data(self, key, value):
        if key not in self.data:
            self.data[key] = []
        if isinstance(value, list):
            self.data[key].extend(value)
        else:
            self.data[key].append(value)
