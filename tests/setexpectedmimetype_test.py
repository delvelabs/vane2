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

from unittest import TestCase

from hammertime.http import Entry

from fixtures import async_test
from vane.setexpectedmimetype import SetExpectedMimeType


class TestSetExpectedMimeType(TestCase):

    @async_test()
    async def test_set_expected_mime_type(self):
        entry = Entry.create("http://example.com/test.html")
        set_mimetype = SetExpectedMimeType()

        await set_mimetype.before_request(entry)

        self.assertEqual(entry.arguments.get("expected_mime_type"), "text/html")

    @async_test()
    async def test_ignore_unknown_extension(self):
        entry = Entry.create("http://example.com/example.test")
        set_mimetype = SetExpectedMimeType()

        await set_mimetype.before_request(entry)

        self.assertNotIn("expected_mime_type", entry.arguments)

    @async_test()
    async def test_ignore_no_extension(self):
        entry = Entry.create("http://example.com/test")
        set_mimetype = SetExpectedMimeType()

        await set_mimetype.before_request(entry)

        self.assertNotIn("expected_mime_type", entry.arguments)
