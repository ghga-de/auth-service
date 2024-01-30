# Copyright 2021 - 2023 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
# for the German Human Genome-Phenome Archive (GHGA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Test user sessions."""

from auth_service.auth_adapter.core.sessions import (
    SESSION_ID_BYTES,
    generate_session_id,
)


def test_generate_session_id():
    """Test generation of session IDs."""
    assert SESSION_ID_BYTES >= 16
    expected_length = SESSION_ID_BYTES * 4 // 3  # because of base64 encoding
    session_ids = []
    for _ in range(100):
        session_id = generate_session_id()
        assert isinstance(session_id, str)
        assert len(session_id) == expected_length
        # check that the session ID contains only URL safe characters
        assert session_id.replace("-", "").replace("_", "").isalnum()
        session_ids.append(session_id)
    # make sure that no duplicates are created
    assert len(session_ids) == len(set(session_ids))
