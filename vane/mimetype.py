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


JS_TYPES = ("application/javascript", "text/javascript", "application/x-javascript")

MIMETYPE_MAPPING = {
    "css": "text/css",
    "csv": "text/csv",
    "eot": "application/vnd.ms-fontobject",
    "gif": "image/gif",
    "htm": "text/html",
    "html": "text/html",
    "ico": "image/x-icon",
    "jpeg": "image/jpeg",
    "jpg": "image/jpeg",
    "js": "application/javascript",
    "json": "application/json",
    "pdf": "application/pdf",
    "png": "image/png",
    "svg": "image/svg+xml",
    "swf": "application/x-shockwave-flash",
    "ttf": "font/ttf",
    "txt": "text/plain",
    "woff": "font/woff",
    "woff2": "font/woff2",
    "xml": "application/xml",
    "zip": "application/zip",
}


def convert_url_to_mimetype(url):
    extension = url.split(".")[-1]
    extension = extension.lower()
    return MIMETYPE_MAPPING.get(extension, None)


def match(type0, type1):
    if type0 in JS_TYPES and type1 in JS_TYPES:
        return True
    return type0.lower() == type1.lower()
