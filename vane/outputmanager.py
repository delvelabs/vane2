import json
from collections import OrderedDict


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
