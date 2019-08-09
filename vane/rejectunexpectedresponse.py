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


class RejectUnexpectedResponse:

    async def after_response(self, entry):
        expectation_count = 0
        matching_expectation_count = 0
        if "expected_status_code" in entry.arguments:
            expectation_count += 1
            if entry.arguments["expected_status_code"] == entry.response.code:
                matching_expectation_count += 1
        if "expected_mime_type" in entry.arguments:
            expectation_count += 1
            if self._mime_type_match_response(entry.arguments["expected_mime_type"], entry.response):
                matching_expectation_count += 1
        if "expected_hash" in entry.arguments and hasattr(entry.result, "hash"):
            expectation_count += 1
            expected_hash = entry.arguments["expected_hash"]
            expected_hash = set(expected_hash) if isinstance(expected_hash, str) else expected_hash
            if entry.result.hash in expected_hash:
                matching_expectation_count += 1

        if expectation_count > 0 and matching_expectation_count == 0:
            raise RejectRequest("Response received didn't match the expectation for the request.")

    def _mime_type_match_response(self, expected, response):
        expected_type = expected.split(";")[0]
        received_type = response.headers.get("content-type", "").split(";")[0]
        return received_type == expected_type
