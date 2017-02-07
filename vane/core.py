from hammertime import HammerTime
from hammertime.rules import IgnoreLargeBody, RejectStatusCode
from .versionidentification import VersionIdentification
from .hash import HashResponse
from .activepluginsfinder import ActivePluginsFinder
from .activethemesfinder import ActiveThemesFinder

import json

from os.path import join, dirname


class Vane:

    def __init__(self):
        self.hammertime = HammerTime(retry_count=1)
        self.config_hammertime()
        self.database = None
        self.output_manager = OutputManager()

    def config_hammertime(self):
        self.hammertime.heuristics.add_multiple([RejectStatusCode(range(400, 500)), IgnoreLargeBody(), HashResponse()])

    async def scan_target(self, url):
        self._load_database()
        self.output_manager.log_message("scanning %s" % url)

        await self.identify_target_version(url)
        await self.active_plugin_enumeration(url)
        await self.active_theme_enumeration(url)

        await self.hammertime.close()

        self.output_manager.log_message("scan done")

    async def identify_target_version(self, url):
        self.output_manager.log_message("Identifying Wordpress version for %s" % url)

        version_identifier = VersionIdentification(self.hammertime)
        # TODO put in _load_database?
        version_identifier.load_files_signatures(join(dirname(__file__), "wordpress_vane2_versions.json"))

        version = await version_identifier.identify_version(url)
        self.output_manager.set_wordpress_version(version)

    async def active_plugin_enumeration(self, url, popular=True, vulnerable=False):
        plugin_finder = ActivePluginsFinder(self.hammertime, url)
        plugin_finder.load_plugins_files_signatures(dirname(__file__))  # TODO use user input for path?
        if popular:
            plugins, errors = await plugin_finder.enumerate_popular_plugins()
            for plugin in plugins:
                self.output_manager.add_plugin(plugin['key'])

    async def active_theme_enumeration(self, url, popular=True, vulnerable=False):
        themes_finder = ActiveThemesFinder(self.hammertime, url)
        themes_finder.load_themes_files_signatures(dirname(__file__))  # TODO use user input for path?
        if popular:
            themes, errors = await themes_finder.enumerate_popular_themes()
            for theme in themes:
                self.output_manager.add_theme(theme['key'])

    # TODO
    def _load_database(self):
        # load database
        if self.database is not None:
            self.output_manager.set_vuln_database_version(self.database.get_version())

    def perfom_action(self, action="scan", url=None, database_path=None):
        if action == "scan":
            if url is None:
                raise ValueError("Target url required.")
            self.hammertime.loop.run_until_complete(self.scan_target(url))
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
