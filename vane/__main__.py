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

actions_available = ["scan", "import_data"]

parser = ArgumentParser(description="vane 2.0")
parser.add_argument("action", choices=actions_available)
parser.add_argument("--url", dest="url")
parser.add_argument("--import_path", dest="database_path")
parser.add_argument('-p', dest="popular", action='store_true',
                    help="Search for popular themes/plugins. Can be combined with vulnerable (-v)")
parser.add_argument('-v', dest="vulnerable", action='store_true',
                    help="Search for vulnerable themes/plugins. Can be combined with popular (-p)")
args = parser.parse_args()

vane = Vane()
vane.perform_action(**vars(args))
