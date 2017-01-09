from hammertime import HammerTime
from hammertime.rules import IgnoreLargeBody

import json


class Vane:

    def __init__(self):
        self.hammertime = HammerTime(retry_count=3)
        self.config_hammertime()
        self.json_output = {}
        self.database = None
        self.output_manager = OutputManager()

    def config_hammertime(self):
        try:
            self.hammertime.heuristics.add_multiple([IgnoreLargeBody()])
        except AttributeError:  # An AttributeError is raised when more than one HammerTime instance is created, just ignore it for now.
            pass

    async def do_request(self, url):
        self._log_message("sending request to %s" % url)
        self.hammertime.request(url)

        success = False
        async for entry in self.hammertime.successful_requests():
            success = True

        if success:
            self._log_message("request successful")
        else:
            self._log_message("request failed")

        await self.hammertime.close()

    # TODO
    async def import_openwebvulndatabase(self, database_path, export_path):
        """Import data from openwebvulndb and repackage it in a more compact database."""
        pass

    # TODO
    def get_wordpress_version(self, url):
        pass

    # TODO
    def list_plugins(self, url):
        pass

    # TODO
    def list_themes(self, url):
        pass

    # TODO
    def find_vulnerabilities(self, plugins, themes, wordpress_version):
        pass

    async def scan_target(self, url):
        self._load_database()

        self._log_message("scanning %s" % url)

        wordpress_version = self.get_wordpress_version(url)
        plugins = self.list_plugins(url)
        themes = self.list_themes(url)
        vulnerabilities = self.find_vulnerabilities(plugins, themes, wordpress_version)

        self.json_output["wordpress_version"] = wordpress_version
        self.json_output["plugins"] = plugins
        self.json_output["themes"] = themes
        self.json_output["vulnerabilities"] = vulnerabilities

        self._log_message("scan done")

    # TODO
    def _load_database(self):
        # load database
        if self.database is not None:
            self.json_output["database_version"] = self.database.get_version()

    def perfom_action(self, action="request", url=None, database_path=None):
        if action == "request":
            if url is None:
                raise ValueError("Target url required.")
            self.hammertime.loop.run_until_complete(self.do_request(url))
        elif action == "complete_scan":
            self.hammertime.loop.run_until_complete(self.scan_target(url))
        elif action == "import_data":
            pass
        self.output_manager.json(self.json_output)

    def _log_message(self, message):
        """Print a message to the general log in the json output."""
        if "general_log" not in self.json_output:
            self.json_output["general_log"] = []
        self.json_output["general_log"].append(message)


class OutputManager:

    # TODO add if necessary.
    def log(self, message):
        pass

    def json(self, data):
        print(json.dumps(data, indent=4))
