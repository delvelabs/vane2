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


import json
from collections import OrderedDict
import termcolor


class OutputManager:

    def __init__(self):
        self.data = {}

    def log_message(self, message):
        self._add_data("general_log", message)

    def format(self, data):
        raise NotImplementedError()

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
        print(self.format(self.data))

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
        component_dict = None
        if key in self.data:
            component_dict = self._get_dictionary_with_key_value_pair_in_list('key', component_key, self.data[key])
        if component_dict is None:
            component_dict = OrderedDict([('key', component_key), ('version', version or "No version found")])
            if meta is not None:
                self._add_meta_to_component(component_dict, meta)
            else:
                component_dict["name"] = self._create_component_name_from_key(component_key)
                component_dict.move_to_end("name", False)
                component_dict["url"] = None
            self._add_data(key, component_dict)
        else:
            self._modify_existing_component(component_dict, version, meta)

    def _modify_existing_component(self, component, version, meta):
        def apply_value(key, value):
            if value is not None:
                component[key] = value

        apply_value('version', version)
        if meta is not None:
            apply_value('name', meta.name)
            apply_value('url', meta.url)

    def _add_meta_to_component(self, component_dict, meta):
        component_dict["name"] = meta.name or self._create_component_name_from_key(component_dict["key"])
        component_dict.move_to_end("name", False)
        component_dict["url"] = meta.url

    def _create_component_name_from_key(self, component_key):
        return component_key.split("/")[-1]


class JsonOutput(OutputManager):

    def format(self, data):
        return json.dumps(data, indent=4)


class PrettyOutput(OutputManager):

    def log_message(self, message):
        print("Log:", message)
        super().log_message(message)

    def set_wordpress_version(self, version, meta):
        print("Finding:", "wordpress", version)
        super().set_wordpress_version(version, meta)

    def add_plugin(self, plugin, version, meta):
        print("Finding:", plugin, version)
        super().add_plugin(plugin, version, meta)

    def add_theme(self, theme, version, meta):
        print("Finding:", theme, version)
        super().add_theme(theme, version, meta)

    def format(self, data):
        output = ""
        if "wordpress" in data:
            output += self._format_component(data["wordpress"])
        if "plugins" in data:
            output += self._format_components(data["plugins"], "Plugins")
        if "themes" in data:
            output += self._format_components(data["themes"], "Themes")
        if "general_log" in data:
            output += self._format_log(data["general_log"])
        return output

    def _format_components(self, components, component_group_name):
        output = ""
        output += self._format_line("%s:" % component_group_name, color="blue", bold=True)
        for component in components:
            output += self._format_component(component)
        return output

    def _format_log(self, log):
        output = ""
        output += self._format_line("General Log:", color="blue", bold=True)
        for message in log:
            output += self._format_line(message)
        return output

    def _format_component(self, component):
        string = "{0} version {1}".format(component['name'], component['version'])
        if component['url'] is not None:
            string += "\turl: %s" % component['url']
        output = self._format_line(string, color="green", bold=True)

        if "vulnerabilities" in component:
            output += self._format_line("Vulnerabilities:", color="red", bold=True)
            for vulnerability in component["vulnerabilities"]:
                output += self._format_vulnerability(vulnerability)
        else:
            output += "No known vulnerabilities\n"
        return output + "\n"

    def _format_vulnerability(self, vulnerability):
        formatted_vulnerability = ""
        if "title" in vulnerability:
            formatted_vulnerability += self._format_line(vulnerability['title'], color="yellow", bold=True)
        else:
            formatted_vulnerability += self._format_line(vulnerability['id'])
        if "description" in vulnerability:
            formatted_vulnerability += self._format_line(vulnerability['description'])
        if "affected_versions" in vulnerability:
            versions = vulnerability["affected_versions"][0]
            if "introduced_in" in versions:
                formatted_vulnerability += self._format_line("Introduced in: %s" % versions["introduced_in"])
            if "fixed_in" in versions:
                formatted_vulnerability += self._format_line("Fixed in: %s" % versions["fixed_in"])
        if "references" in vulnerability:
            references = vulnerability["references"]
            formatted_vulnerability += self._format_line("References:")
            for reference in references:
                formatted_vulnerability += self._format_vulnerability_reference(reference, indent_level=1)
        return formatted_vulnerability

    def _format_vulnerability_reference(self, reference, indent_level):
        formatted_reference = ""
        if reference["type"] == "other":
            formatted_reference += self._format_line(reference["url"], indent_level)
        else:
            ref = "{0}: {1}".format(reference["type"], reference["id"])
            if "url" in reference:
                ref += " url: %s" % reference["url"]
            formatted_reference += self._format_line(ref, indent_level)
        return formatted_reference

    def _format_line(self, value, indent_level=0, color=None, highlight_color=None, bold=False):
        if color:
            if bold:
                attrs = ["bold"]
            else:
                attrs = []
            if highlight_color:
                value = termcolor.colored(value, color, highlight_color, attrs=attrs)
            else:
                value = termcolor.colored(value, color, attrs=attrs)
        return "{0}{1}\n".format("\t" * indent_level, value)
