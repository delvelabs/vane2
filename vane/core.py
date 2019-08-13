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


from aiohttp import ClientSession, ClientError
import asyncio
from os.path import join
import re
from hammertime import HammerTime
from hammertime.rules import RejectStatusCode, DynamicTimeout, DetectSoft404, DeadHostDetection
from hammertime.rules.deadhostdetection import OfflineHostException
from hammertime.rules.waf import RejectWebApplicationFirewall
from hammertime.ruleset import HammerTimeException, RejectRequest, StopRequest
from hammertime.engine.aiohttp import AioHttpEngine
from hammertime.config import custom_event_loop
from hammertime.rules.sampling import ContentHashSampling, ContentSampling, ContentSimhashSampling
from hammertime.rules import RejectCatchAllRedirect, FollowRedirects
from openwebvulndb.common.schemas import FileListSchema, VulnerabilityListGroupSchema, VulnerabilitySchema, \
    MetaListSchema
from openwebvulndb.common.serialize import clean_walk

from .versionidentification import VersionIdentification
from .hash import HashResponse
from .activecomponentfinder import ActiveComponentFinder
from .retryonerrors import RetryOnErrors
from .utils import load_model_from_file, validate_url, normalize_url
from .filefetcher import FileFetcher
from .vulnerabilitylister import VulnerabilityLister
from .passivepluginsfinder import PassivePluginsFinder
from .passivethemesfinder import PassiveThemesFinder
from .outputmanager import PrettyOutput, JsonOutput
from .database import Database
from .setexpectedmimetype import SetExpectedMimeType
from .rejectunexpectedresponse import RejectUnexpectedResponse


class Vane:

    def __init__(self, output_format="pretty"):
        self.database = None
        self.output_manager = JsonOutput() if output_format == "json" else PrettyOutput()
        self.hammertime = None

    def initialize_hammertime(self, proxy=None, verify_ssl=True, ca_certificate_file=None):
        loop = custom_event_loop()
        if proxy is not None and verify_ssl and ca_certificate_file is None:
            self.output_manager.log_message("Verifying SSL authentication of the target over a proxy without providing "
                                            "a CA certificate. Scan may fail if target is a https website.")
        request_engine = AioHttpEngine(loop=loop, verify_ssl=verify_ssl, ca_certificate_file=ca_certificate_file)
        self.hammertime = HammerTime(loop=loop, retry_count=3, proxy=proxy, request_engine=request_engine)
        self.config_hammertime()

    def config_hammertime(self):
        global_heuristics = [DynamicTimeout(0.05, 2), RetryOnErrors(range(500, 503)), DeadHostDetection(threshold=200),
                             ContentHashSampling(), ContentSampling(), ContentSimhashSampling()]
        soft_404 = DetectSoft404()
        follow_redirects = FollowRedirects()
        reject_error_code = RejectStatusCode(range(400, 600))
        heuristics = [reject_error_code, RejectWebApplicationFirewall(), RejectCatchAllRedirect(),
                      follow_redirects, soft_404, HashResponse(), SetExpectedMimeType(), RejectUnexpectedResponse()]
        self.hammertime.heuristics.add_multiple(global_heuristics)
        self.hammertime.heuristics.add_multiple(heuristics)
        soft_404.child_heuristics.add_multiple(global_heuristics)
        follow_redirects.child_heuristics.add(reject_error_code)
        follow_redirects.child_heuristics.add_multiple(global_heuristics)

    def set_proxy(self, proxy_address):
        self.hammertime.set_proxy(proxy_address)

    async def scan_target(self, url, popular, vulnerable, passive_only=False):
        self.output_manager.log_message("scanning %s" % url)

        if not validate_url(url):
            self.output_manager.log_message("%s is not a valid url" % url)
            await self.hammertime.close()
            return

        url = normalize_url(url)

        input_path = self.database.database_directory

        try:
            if not await self.is_wordpress(url):
                raise ValueError("target is not a valid Wordpress site")

            wordpress_version = await self.identify_target_version(url, input_path,
                                                                   file_fetcher=FileFetcher(self.hammertime, url),
                                                                   version_identifier=VersionIdentification())

            plugins_version = await self.plugin_enumeration(url, popular, vulnerable, input_path,
                                                            passive_only=passive_only)
            theme_versions = await self.theme_enumeration(url, popular, vulnerable, input_path,
                                                          passive_only=passive_only)

            file_name = join(input_path, "vane2_vulnerability_database.json")
            vulnerability_list_group, errors = load_model_from_file(file_name, VulnerabilityListGroupSchema())

            self.list_component_vulnerabilities(wordpress_version, vulnerability_list_group, no_version_match_all=False)
            self.list_component_vulnerabilities(plugins_version, vulnerability_list_group, no_version_match_all=True)
            self.list_component_vulnerabilities(theme_versions, vulnerability_list_group, no_version_match_all=True)

        except ValueError as error:
            self.output_manager.log_message(str(error))
        except OfflineHostException:
            self.output_manager.log_message("%s seems to be offline, aborting scan" % url)

        self.output_manager.log_message("scan done")

    async def is_wordpress(self, url):
        try:
            entry = await self.hammertime.request(url)
            headers = entry.response.headers
            try:
                if re.search("/wp-json/", headers["link"]):
                    return True
            except KeyError:
                pass
            return re.search("/wp-content/", entry.response.content)
        except RejectRequest:
            return False
        except StopRequest:
            raise OfflineHostException()

    async def identify_target_version(self, url, input_path, *, file_fetcher, version_identifier):
        self.output_manager.log_message("Identifying Wordpress version for %s" % url)

        # TODO put in _load_database?
        file_name = join(input_path, "vane2_wordpress_versions.json")
        file_list, errors = load_model_from_file(file_name, FileListSchema())
        meta_list, errors = self._load_meta_list("wordpress", input_path)
        for error in errors:
            self.output_manager.log_message(repr(error))

        key, fetched_files = await file_fetcher.request_files("wordpress", file_list)
        if len(fetched_files) == 0:
            raise ValueError("target is not a valid Wordpress site")
        files_with_version = await self._get_files_for_version_identification(url)
        timeout_file_count = file_fetcher.timeouts
        total_file_count = len(file_list.files)
        confidence_level_of_fetched_files = (total_file_count - timeout_file_count) / total_file_count
        version_identifier.set_confidence_level_of_fetched_files(confidence_level_of_fetched_files)
        version = version_identifier.identify_version(fetched_files, file_list, files_with_version)
        self.output_manager.set_wordpress_version(version, meta_list.get_meta("wordpress"))
        return {'wordpress': version}

    async def plugin_enumeration(self, url, popular, vulnerable, input_path, passive_only=False):
        meta_list, errors = self._load_meta_list("plugins", input_path)
        plugins_version = {}

        if not passive_only:
            plugins_version = await self.active_plugin_enumeration(url, popular, vulnerable, input_path, meta_list)

        try:
            site_homepage = await self._request_target_home_page(url)
            plugins = self.passive_plugin_enumeration(site_homepage, meta_list)
        except HammerTimeException as e:
            self.output_manager.log_message("Passive plugin enumeration failed: %s" % repr(e))
            plugins = {}

        for plugin_key, version in plugins.items():
            if plugin_key not in plugins_version:
                plugins_version[plugin_key] = version
                meta = meta_list.get_meta(plugin_key)
                self.output_manager.add_plugin(plugin_key, version, meta)
            elif version is not None:
                plugins_version[plugin_key] = version
                self.output_manager.add_plugin(plugin_key, version, None)
        return plugins_version

    async def theme_enumeration(self, url, popular, vulnerable, input_path, passive_only=False):
        meta_list, errors = self._load_meta_list("themes", input_path)
        themes_version = {}

        if not passive_only:
            themes_version = await self.active_theme_enumeration(url, popular, vulnerable, input_path, meta_list)

        try:
            site_homepage = await self._request_target_home_page(url)
            themes_key = self.passive_theme_enumeration(site_homepage, meta_list)
        except HammerTimeException as e:
            self.output_manager.log_message("Passive theme enumeration failed: %s" % repr(e))
            themes_key = []

        for theme in themes_key:
            if theme not in themes_version:
                themes_version[theme] = None
                meta = meta_list.get_meta(theme)
                self.output_manager.add_theme(theme, themes_version[theme], meta)

        return themes_version

    async def active_plugin_enumeration(self, url, popular, vulnerable, input_path, meta_list):
        plugins_version = {}
        self._log_active_enumeration_type("plugins", popular, vulnerable)

        component_finder = ActiveComponentFinder(self.hammertime, url)

        errors = component_finder.load_components_identification_file(input_path, "plugins", popular, vulnerable)

        for error in errors:
            self.output_manager.log_message(repr(error))

        version_identification = VersionIdentification()

        async for plugin in component_finder.enumerate_found():
            plugin_file_list = component_finder.get_component_file_list(plugin['key'])
            version = version_identification.identify_version(plugin['files'], plugin_file_list)
            self.output_manager.add_plugin(plugin['key'], version, meta_list.get_meta(plugin['key']))
            plugins_version[plugin['key']] = version
        return plugins_version

    async def active_theme_enumeration(self, url, popular, vulnerable, input_path, meta_list):
        themes_version = {}
        self._log_active_enumeration_type("themes", popular, vulnerable)

        component_finder = ActiveComponentFinder(self.hammertime, url)

        errors = component_finder.load_components_identification_file(input_path, "themes", popular, vulnerable)

        for error in errors:
            self.output_manager.log_message(repr(error))

        version_identification = VersionIdentification()

        async for theme in component_finder.enumerate_found():
            theme_file_list = component_finder.get_component_file_list(theme['key'])
            version = version_identification.identify_version(theme['files'], theme_file_list)
            self.output_manager.add_theme(theme['key'], version, meta_list.get_meta(theme['key']))
            themes_version[theme['key']] = version
        return themes_version

    def passive_plugin_enumeration(self, html_page, meta_list):
        passive_plugins_finder = PassivePluginsFinder(meta_list)
        plugin_keys = passive_plugins_finder.list_plugins(html_page)
        return plugin_keys

    def passive_theme_enumeration(self, hammertime_response, meta_list):
        passive_theme_finder = PassiveThemesFinder(meta_list)
        theme_keys = passive_theme_finder.list_themes(hammertime_response)
        return theme_keys

    async def _get_files_for_version_identification(self, url):
        files_path = ["wp-login.php", "wp-links-opml.php"]
        file_response_list = []
        try:
            homepage_response = await self._request_target_home_page(url)
            file_response_list.append(homepage_response)
        except HammerTimeException:
            pass
        for path in files_path:
            try:
                entry = await self.hammertime.request(url + path)
                file_response_list.append(entry.response)
            except HammerTimeException:
                pass
        return file_response_list

    async def _request_target_home_page(self, url):
        try:
            entry = await self.hammertime.request(url)
            return entry.response
        except HammerTimeException:
            raise

    def list_component_vulnerabilities(self, components_version, vulnerability_list_group, no_version_match_all):
        vulnerability_lister = VulnerabilityLister()
        components_vulnerabilities = {}
        for key, version in components_version.items():
            vulnerability_list = self._get_vulnerability_list_for_key(key, vulnerability_list_group)
            if vulnerability_list is not None:
                vulnerabilities = vulnerability_lister.list_vulnerabilities(version, vulnerability_list,
                                                                            no_version_match_all=no_version_match_all)
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

    async def _load_database(self, loop, database_path, auto_update_frequency=7, no_update=False):
        async with ClientSession(loop=loop) as aiohttp_session:
            self.database = Database(self.output_manager, aiohttp_session, auto_update_frequency)
            self.database.configure_update_repository("delvelabs", "vane2-data")
            try:
                await self.database.load_data(database_path, no_update=no_update)
            except ClientError:
                self.output_manager.log_message("Database update failed: connection error.")
            except AssertionError:
                self.output_manager.log_message("Database update failed: bad status code in server's response.")
            except OSError as e:
                self.output_manager.log_message("Database installation failed:\n%s" % e)
            self.output_manager.set_vuln_database_version(self.database.current_version)

    def _load_meta_list(self, key, input_path):
        file_name = join(input_path, "vane2_%s_meta.json" % key)
        return load_model_from_file(file_name, MetaListSchema())

    def close(self, loop):
        if self.hammertime is not None:
            loop.run_until_complete(self.hammertime.close())
        loop.close()

    def perform_action(self, action="scan", url=None, database_path=".", popular=False, vulnerable=False,
                       passive=False, proxy=None, verify_ssl=True, ca_certificate_file=None, auto_update_frequency=7,
                       no_update=False, **kwargs):
        loop = custom_event_loop()
        if action == "scan":
            if url is None:
                raise ValueError("Target url required.")
            loop.run_until_complete(self._load_database(loop, database_path, int(auto_update_frequency), no_update))
            if self.database.database_directory is not None:
                self.initialize_hammertime(proxy=proxy, verify_ssl=verify_ssl, ca_certificate_file=ca_certificate_file)
                try:
                    loop.run_until_complete(self.scan_target(url, popular=popular, vulnerable=vulnerable,
                                                             passive_only=passive))
                except asyncio.CancelledError:
                    self.output_manager.log_message("Scan interrupted.")
        elif action == "import-data":
            loop.run_until_complete(self._load_database(loop, database_path, Database.ALWAYS_CHECK_FOR_UPDATE))

        self.close(loop)
        self.output_manager.flush()
