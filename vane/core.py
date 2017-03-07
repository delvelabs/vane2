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
from hammertime.rules import RejectStatusCode
from .versionidentification import VersionIdentification
from .hash import HashResponse
from .activecomponentfinder import ActiveComponentFinder
from .retryonerrors import RetryOnErrors
from openwebvulndb.common.schemas import FileListSchema, VulnerabilityListGroupSchema, VulnerabilitySchema, \
    MetaListSchema
from openwebvulndb.common.serialize import clean_walk
from .utils import load_model_from_file, validate_url, normalize_url
from .filefetcher import FileFetcher
from .vulnerabilitylister import VulnerabilityLister

import json

from os.path import join, dirname
from collections import OrderedDict


class Vane:

    def __init__(self):
        self.hammertime = HammerTime(retry_count=3)
        self.config_hammertime()
        self.database = None
        self.output_manager = OutputManager()

    def config_hammertime(self):
        self.hammertime.heuristics.add_multiple([RetryOnErrors(range(502, 503)), RejectStatusCode(range(400, 600)),
                                                 HashResponse()])

    async def scan_target(self, url, popular, vulnerable):
        self._load_database()
        self.output_manager.log_message("scanning %s" % url)

        if not validate_url(url):
            self.output_manager.log_message("%s is not a valid url" % url)
            await self.hammertime.close()
            return

        url = normalize_url(url)

        # TODO use user input for path?
        input_path = dirname(__file__)

        try:
            wordpress_version = await self.identify_target_version(url, input_path)
            plugins_version = await self.active_plugin_enumeration(url, popular, vulnerable, input_path)
            theme_versions = await self.active_theme_enumeration(url, popular, vulnerable, input_path)

            file_name = join(input_path, "vane2_vulnerability_database.json")
            vulnerability_list_group, errors = load_model_from_file(file_name, VulnerabilityListGroupSchema())

            self.list_component_vulnerabilities(wordpress_version, vulnerability_list_group)
            self.list_component_vulnerabilities(plugins_version, vulnerability_list_group)
            self.list_component_vulnerabilities(theme_versions, vulnerability_list_group)

        except ValueError as error:
            self.output_manager.log_message(str(error))
        await self.hammertime.close()

        self.output_manager.log_message("scan done")

    async def identify_target_version(self, url, input_path):
        self.output_manager.log_message("Identifying Wordpress version for %s" % url)

        version_identifier = VersionIdentification()
        file_fetcher = FileFetcher(self.hammertime, url)

        # TODO put in _load_database?
        file_name = join(input_path, "vane2_wordpress_versions.json")
        file_list, errors = load_model_from_file(file_name, FileListSchema())
        meta_list, errors = self._load_meta_list("wordpress", input_path)
        for error in errors:
            self.output_manager.log_message(repr(error))

        key, fetched_files = await file_fetcher.request_files("wordpress", file_list)
        if len(fetched_files) == 0:
            raise ValueError("target is not a valid Wordpress site")
        version = version_identifier.identify_version(fetched_files, file_list)
        self.output_manager.set_wordpress_version(version, meta_list.get_meta("wordpress"))
        return {'wordpress': version}

    async def active_plugin_enumeration(self, url, popular, vulnerable, input_path):
        plugins_version = {}
        self._log_active_enumeration_type("plugins", popular, vulnerable)

        component_finder = ActiveComponentFinder(self.hammertime, url)

        errors = component_finder.load_components_identification_file(input_path, "plugins", popular, vulnerable)

        for error in errors:
            self.output_manager.log_message(repr(error))

        meta_list, errors = self._load_meta_list("plugins", input_path)

        version_identification = VersionIdentification()

        async for plugin in component_finder.enumerate_found():
            plugin_file_list = component_finder.get_component_file_list(plugin['key'])
            version = version_identification.identify_version(plugin['files'], plugin_file_list)
            self.output_manager.add_plugin(plugin['key'], version, meta_list.get_meta(plugin['key']))
            plugins_version[plugin['key']] = version
        return plugins_version

    async def active_theme_enumeration(self, url, popular, vulnerable, input_path):
        themes_version = {}
        self._log_active_enumeration_type("themes", popular, vulnerable)

        component_finder = ActiveComponentFinder(self.hammertime, url)

        errors = component_finder.load_components_identification_file(input_path, "themes", popular, vulnerable)

        for error in errors:
            self.output_manager.log_message(repr(error))

        meta_list, errors = self._load_meta_list("themes", input_path)

        version_identification = VersionIdentification()

        async for theme in component_finder.enumerate_found():
            theme_file_list = component_finder.get_component_file_list(theme['key'])
            version = version_identification.identify_version(theme['files'], theme_file_list)
            self.output_manager.add_theme(theme['key'], version, meta_list.get_meta(theme['key']))
            themes_version[theme['key']] = version
        return themes_version

    def list_component_vulnerabilities(self, components_version, vulnerability_list_group):
        vulnerability_lister = VulnerabilityLister()
        components_vulnerabilities = {}
        for key, version in components_version.items():
            vulnerability_list = self._get_vulnerability_list_for_key(key, vulnerability_list_group)
            if vulnerability_list is not None:
                vulnerabilities = vulnerability_lister.list_vulnerabilities(version, vulnerability_list)
                components_vulnerabilities[key] = vulnerabilities
                self._log_vulnerabilities(key, vulnerabilities)
        return components_vulnerabilities

    def _log_vulnerabilities(self, key, vulnerabilities):
        vulnerability_schema = VulnerabilitySchema()
        for vulnerability in vulnerabilities:
            data, errors = vulnerability_schema.dump(vulnerability)
            clean_walk(data)
            self.output_manager.add_vulnerability(key, data)

    def _get_vulnerability_list_for_key(self, key, vulnerability_list_group):
        for vuln_list in vulnerability_list_group.vulnerability_lists:
            if vuln_list.key == key:
                return vuln_list
        return None

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

    def _load_meta_list(self, key, input_path):
        file_name = join(input_path, "vane2_%s_meta.json" % key)
        return load_model_from_file(file_name, MetaListSchema())

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

    def set_wordpress_version(self, version, meta):
        wordpress_dict = OrderedDict([("version", version)])
        if meta is not None:
            self._add_meta_to_component(wordpress_dict, meta)
        self.data["wordpress"] = wordpress_dict

    def set_vuln_database_version(self, version):
        self.data["vuln_database_version"] = version

    def add_plugin(self, plugin, version, meta):
        self._add_component("plugins", plugin, version, meta)

    def add_theme(self, theme, version, meta):
        self._add_component("themes", theme, version, meta)

    def add_vulnerability(self, key, vulnerability):
        component_dict = self._get_component_dictionary(key)
        if component_dict is not None:
            self._add_data("vulnerabilities", vulnerability, component_dict)

    def flush(self):
        print(self._format(self.data))

    def _add_data(self, key, value, container=None):
        if container is None:
            container = self.data
        if key not in container:
            container[key] = []
        if isinstance(value, list):
            container[key].extend(value)
        else:
            container[key].append(value)

    def _get_dictionary_with_key_value_pair_in_list(self, key, value, list):
        for dictionary in list:
            if key in dictionary and dictionary[key] == value:
                return dictionary
        return None

    def _get_component_dictionary(self, key):
        if "/" in key:
            key_path = key.split("/")
            return self._get_dictionary_with_key_value_pair_in_list("key", key, self.data[key_path[0]])
        if key in self.data:
            return self.data[key]
        return None

    def _add_component(self, key, component_key, version, meta):
        component_dict = OrderedDict([('key', component_key), ('version', version or "No version found")])
        if meta is not None:
            self._add_meta_to_component(component_dict, meta)
        self._add_data(key, component_dict)

    def _add_meta_to_component(self, component_dict, meta):
        if meta.name is not None:
            component_dict["name"] = meta.name
            component_dict.move_to_end("name", False)
        if meta.url is not None:
            component_dict["url"] = meta.url
