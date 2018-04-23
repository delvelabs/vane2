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

from argparse import ArgumentParser
from .core import Vane

actions_available = ["scan", "import-data"]

parser = ArgumentParser(description="vane 2.0")
parser.add_argument("action", choices=actions_available)
parser.add_argument("--url", dest="url")
parser.add_argument("--import-path", dest="database_path", default=".")
parser.add_argument('-p', dest="popular", action='store_true',
                    help="Search for popular themes/plugins. Can be combined with vulnerable (-v)")
parser.add_argument('-v', dest="vulnerable", action='store_true',
                    help="Search for vulnerable themes/plugins. Can be combined with popular (-p)")
parser.add_argument('--passive', dest='passive', action='store_true',
                    help="Only use passive detection for themes and plugins")
parser.add_argument('--proxy', dest='proxy', help="Address of the HTTP proxy to be used by Vane")
parser.add_argument('--no-ssl-validation', dest='verify_ssl', action='store_false', help="Don't perform ssl "
                                                                                         "authentication.")
parser.add_argument('--ca-cert', dest='ca_certificate_file', help='The ca certificate file of the proxy used for the '
                                                                  'scan. Required if scanning an https website over a '
                                                                  'proxy and verifying ssl authentication.')
parser.add_argument('--auto-update-frequency', dest='auto_update_frequency',
                    help='The delay in days between two auto updates of the database (default is 7 days)', default=7)
parser.add_argument('--no-update', dest='no_update', help="Don't attempt a data update. Program terminated if files are"
                                                          " missing or no database is found, ", action='store_true')
parser.add_argument('--output-format', dest='output_format', default='pretty', help='Format for the scan output("pretty'
                                                                                    '" or "json"), default is pretty')
args = parser.parse_args()


def main():
    vane = Vane(args.output_format)
    vane.perform_action(**vars(args))


if __name__ == '__main__':
    main()
