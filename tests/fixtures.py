# vane 2.0: A Wordpress vulnerability assessment tool.
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

from collections import OrderedDict


def wrap_lists_in_unordered_lists(iterable):
    """Recursively iterate over the contents of a iterable and wrap all lists elements into UnorderedList"""
    if type(iterable) == dict or type(iterable) == OrderedDict:
        for key, value in iterable.items():
            iterable[key] = wrap_lists_in_unordered_lists(value)
        return iterable
    elif type(iterable) == list:
        li = [wrap_lists_in_unordered_lists(element) for element in iterable]
        return UnorderedList(li)
    else:
        return iterable


class UnorderedList:
    """Wrapper for a list, used for equality assertion based on orderless elements occurrence."""

    def __init__(self, list):
        self.list = list

    def __eq__(self, other):
        li = list(self.list)
        try:
            for element in other:
                li.remove(element)
        except ValueError:
            return False
        return len(li) == 0
