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


from setuptools import setup, find_packages

from vane.__version__ import __version__


setup(
    name='vane2',
    version=__version__,
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'vane = vane.__main__:main'
        ]
    },
    install_requires=[
        'lxml>=4.0.0,<5.0.0',
        'termcolor==1.1.0',
        'hammertime-http>=0.6.0,<0.7.0',
        'openwebvulndb-tools>=1.0.0,<2',
    ],
)
