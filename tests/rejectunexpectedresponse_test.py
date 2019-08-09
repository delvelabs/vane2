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

from hammertime.http import Entry, Request, Result, StaticResponse
from hammertime.ruleset import RejectRequest

from fixtures import async_test
from vane.hash import HashResponse
from vane.rejectunexpectedresponse import RejectUnexpectedResponse


class TestRejectUnexpectedResponse(TestCase):

    @async_test()
    async def test_after_response_raise_reject_request_if_response_matches_none_of_the_expectations(self, loop):
        expected_hash = {"123", "456"}
        expected_status_code = 200
        expected_mime_type = "image/png"

        response = StaticResponse(302, headers={"content-type": "text/html; charset=utf-8"}, content="html content")
        request = Request("http://example.com/")
        arguments = {"expected_hash": expected_hash, "expected_mime_type": expected_mime_type,
                     "expected_status_code": expected_status_code, "hash_algo": "sha256"}
        entry = Entry(request, response, Result(), arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        with self.assertRaises(RejectRequest):
            await reject_response.after_response(entry)

    @async_test()
    async def test_after_response_accept_request_if_response_matches_one_of_the_expectations(self, loop):
        expected_hash = {"123", "456"}
        expected_status_code = 200
        expected_mime_type = "image/png"

        response = StaticResponse(302, headers={"content-type": "image/png"}, content="image data")
        request = Request("http://example.com/")
        arguments = {"expected_hash": expected_hash, "expected_mime_type": expected_mime_type,
                     "expected_status_code": expected_status_code, "hash_algo": "sha256"}
        entry = Entry(request, response, Result(), arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        await reject_response.after_response(entry)

    @async_test()
    async def test_after_response_ignore_subtype_for_mime_type_match(self, loop):
        response = StaticResponse(200, headers={"content-type": "text/html; charset=utf-8"}, content="html content")
        request = Request("http://example.com/")
        entry = Entry(request, response, Result(), {"expected_mime_type": "text/html"})
        reject_response = RejectUnexpectedResponse()

        await reject_response.after_response(entry)
