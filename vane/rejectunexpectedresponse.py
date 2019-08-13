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


from hammertime.ruleset import RejectRequest

from .mimetype import match


class RejectUnexpectedResponse:

    async def on_request_successful(self, entry):
        if "expected_hash" not in entry.arguments:
            return
        if len(entry.response.raw) == 0:
            raise RejectRequest("Response received didn't match the expectation for the request.")
        status_code_match = None
        mime_type_match = None
        if self._response_hash_matches_expected_hash(entry):
            return
        if "expected_status_code" in entry.arguments:
            status_code_match = self._status_code_match(entry)
        if "expected_mime_type" in entry.arguments:
            mime_type_match = self._mime_type_match_response(entry.arguments["expected_mime_type"], entry.response)
            if mime_type_match is True and entry.arguments["expected_mime_type"] == "text/html":
                mime_type_match = None

        if not mime_type_match and not status_code_match:
            raise RejectRequest("Response received didn't match the expectation for the request.")
        elif mime_type_match is None and status_code_match is False:
            raise RejectRequest("Response received didn't match the expectation for the request.")

    def _response_hash_matches_expected_hash(self, entry):
        expected_hash = entry.arguments["expected_hash"]
        expected_hash = {expected_hash} if isinstance(expected_hash, str) else expected_hash
        return entry.result.hash in expected_hash

    def _mime_type_match_response(self, expected, response):
        expected_type = expected.split(";")[0]
        received_type = response.headers.get("content-type", "").split(";")[0]
        return match(received_type, expected_type)

    def _status_code_match(self, entry):
        if len(entry.result.redirects) > 0:
            status_code = entry.result.redirects[0].response.code
        else:
            status_code = entry.response.code
        return entry.arguments["expected_status_code"] == status_code
