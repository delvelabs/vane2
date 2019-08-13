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

from hammertime.http import Entry, StaticResponse
from hammertime.ruleset import RejectRequest

from fixtures import async_test
from vane.hash import hash_data, HashResponse
from vane.rejectunexpectedresponse import RejectUnexpectedResponse


class TestRejectUnexpectedResponse(TestCase):

    @async_test()
    async def test_on_request_successful_raise_reject_request_if_response_matches_none_of_the_expectations(self):
        expected_hash = {"123", "456"}
        expected_status_code = 200
        expected_mime_type = "image/png"

        response = StaticResponse(200, headers={"content-type": "text/html; charset=utf-8"}, content="html content")
        arguments = {"expected_hash": expected_hash, "expected_mime_type": expected_mime_type,
                     "expected_status_code": expected_status_code, "hash_algo": "sha256"}
        entry = self.create_redirect("http://example.com/", final_response=response, arguments=arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        with self.assertRaises(RejectRequest):
            await reject_response.on_request_successful(entry)

    @async_test()
    async def test_on_request_successful_accept_request_if_response_matches_all_of_the_expectations(self):
        content = "image data"
        expected_hash = hash_data(content.encode(), "sha256")
        expected_hash = {"123", "456", expected_hash}
        expected_status_code = 200
        expected_mime_type = "image/png"

        response = StaticResponse(200, headers={"content-type": "image/png"}, content=content)
        arguments = {"expected_hash": expected_hash, "expected_mime_type": expected_mime_type,
                     "expected_status_code": expected_status_code, "hash_algo": "sha256"}
        entry = Entry.create("http://example.com/", response=response, arguments=arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        await reject_response.on_request_successful(entry)

    @async_test()
    async def test_on_request_successful_use_first_response_code_for_match_if_redirect(self):
        expected_status_code = 200
        expected_mime_type = "text/plain"

        response = StaticResponse(200, headers={"content-type": "text/html"}, content="not-the-expected-content")
        arguments = {"expected_mime_type": expected_mime_type, "expected_status_code": expected_status_code,
                     "hash_algo": "sha256", "expected_hash": "123"}
        entry = self.create_redirect("http://example.com/", final_response=response, arguments=arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        with self.assertRaises(RejectRequest):
            await reject_response.on_request_successful(entry)

    @async_test()
    async def test_on_request_successful_accept_request_if_response_hash_matches_expected_hash(self):
        content = "data"
        expected_hash = hash_data(content.encode(), "sha256")
        expected_status_code = 200
        expected_mime_type = "text/html"

        response = StaticResponse(200, headers={"content-type": "application/javascript"}, content=content)
        arguments = {"expected_hash": expected_hash, "expected_mime_type": expected_mime_type,
                     "expected_status_code": expected_status_code, "hash_algo": "sha256"}
        entry = self.create_redirect("http://example.com/", final_response=response, arguments=arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        await reject_response.on_request_successful(entry)

    @async_test()
    async def test_on_request_successful_accept_request_if_code_and_content_type_match(self):
        expected_hash = "some-random-hash"
        expected_status_code = 200
        expected_mime_type = "text/html"

        response = StaticResponse(200, headers={"content-type": "text/html"}, content="not-the-expected-content")
        arguments = {"expected_hash": expected_hash, "expected_mime_type": expected_mime_type,
                     "expected_status_code": expected_status_code, "hash_algo": "sha256"}
        entry = Entry.create("http://example.com/", response=response, arguments=arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        await reject_response.on_request_successful(entry)

    @async_test()
    async def test_on_request_successful_accept_request_if_only_content_type_match_and_content_type_is_not_html(self):
        expected_hash = "some-random-hash"
        expected_status_code = 200
        expected_mime_type = "image/svg+xml"

        response = StaticResponse(200, headers={"content-type": "image/svg+xml"}, content="not-the-expected-content")
        arguments = {"expected_hash": expected_hash, "expected_mime_type": expected_mime_type,
                     "expected_status_code": expected_status_code, "hash_algo": "sha256"}
        entry = self.create_redirect("http://example.com/", final_response=response, arguments=arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        await reject_response.on_request_successful(entry)

    @async_test()
    async def test_on_request_successful_reject_request_if_hash_and_content_type_dont_match(self):
        expected_hash = hash_data(b"expected page", "sha256")
        expected_status_code = 200
        expected_mime_type = "application/javascript"
        response = StaticResponse(200, headers={"content-type": "text/html"}, content="page not found")
        arguments = {"expected_hash": expected_hash, "expected_mime_type": expected_mime_type,
                     "expected_status_code": expected_status_code, "hash_algo": "sha256"}
        entry = self.create_redirect("http://example.com/", final_response=response, arguments=arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        with self.assertRaises(RejectRequest):
            await reject_response.on_request_successful(entry)

    @async_test()
    async def test_on_request_successful_content_type_is_not_determinant_if_it_is_text_html(self):
        expected_hash = hash_data(b"expected page", "sha256")
        expected_status_code = 200
        expected_mime_type = "text/html"
        response = StaticResponse(200, headers={"content-type": "text/html"}, content="page not found")
        arguments = {"expected_hash": expected_hash, "expected_mime_type": expected_mime_type,
                     "expected_status_code": expected_status_code, "hash_algo": "sha256"}
        entry = self.create_redirect("http://example.com/", final_response=response, arguments=arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        with self.assertRaises(RejectRequest):
            await reject_response.on_request_successful(entry)

    @async_test()
    async def test_on_request_successful_reject_request_if_hash_and_code_dont_match_and_content_type_is_not_set(self):
        expected_hash = hash_data(b"expected page", "sha256")
        expected_status_code = 200
        response = StaticResponse(200, headers={"content-type": "text/html"}, content="page not found")
        arguments = {"expected_hash": expected_hash, "expected_status_code": expected_status_code,
                     "hash_algo": "sha256"}
        entry = self.create_redirect("http://example.com/", final_response=response, arguments=arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        with self.assertRaises(RejectRequest):
            await reject_response.on_request_successful(entry)

    @async_test()
    async def test_on_request_successful_ignore_encoding_for_mime_type_match(self):
        response = StaticResponse(200, headers={"content-type": "text/html; charset=utf-8"}, content="html content")
        entry = Entry.create("http://example.com/", response=response, arguments={"expected_mime_type": "text/html"})
        reject_response = RejectUnexpectedResponse()

        await reject_response.on_request_successful(entry)

    @async_test()
    async def test_hash_of_empty_file_never_match(self):
        empty_file_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        expected_status_code = 200
        expected_mime_type = "image/png"

        response = StaticResponse(200, headers={}, content="")
        arguments = {"expected_hash": empty_file_hash, "expected_mime_type": expected_mime_type,
                     "expected_status_code": expected_status_code, "hash_algo": "sha256"}
        entry = Entry.create("http://example.com/", response=response, arguments=arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        with self.assertRaises(RejectRequest):
            await reject_response.on_request_successful(entry)

    @async_test()
    async def test_on_request_successful_ignore_request_if_no_expected_hash(self):
        expected_status_code = 200
        response = StaticResponse(200, headers={"content-type": "text/plain"}, content="page not found")
        arguments = {"expected_status_code": expected_status_code, "expected_mime_type": "image/png",
                     "hash_algo": "sha256"}
        entry = self.create_redirect("http://example.com/", final_response=response, arguments=arguments)

        hash_response = HashResponse()
        reject_response = RejectUnexpectedResponse()
        await hash_response.after_response(entry)

        await reject_response.on_request_successful(entry)

    def create_redirect(self, url, final_response, arguments):
        initial_response = StaticResponse(302, headers={"location": "http://example.com/redirect"})
        initial_entry = Entry.create(url, response=initial_response, arguments=arguments)
        final_entry = Entry.create(url, response=final_response, arguments=arguments)
        final_entry.result.redirects = [initial_entry, final_entry]
        return final_entry
