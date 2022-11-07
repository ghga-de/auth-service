# Copyright 2021 - 2022 Universität Tübingen, DKFZ and EMBL
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

"""Test the REST API"""

from fastapi import status

from auth_service.user_management.user_registry.deps import get_user_dao

from ....fixtures.utils import DummyUserDao
from ..fixtures import (  # noqa: F401; pylint: disable=unused-import
    fixture_client,
    fixture_client_with_db,
)

CLAIM_DATA = dict(
    user_id="som-internal-user-id",
    visa_type="GHGA_ROLE",
    visa_value="data-steward@ghga.de",
    assertion_date="2022-09-01T12:00:00",
    valid_from="2022-10-01T12:00:00",
    valid_until="2022-10-31T12:00:00",
    source="https://ghga.de",
)


def test_get_from_root(client):
    """Test that a simple GET request passes."""

    response = client.get("/")

    assert response.status_code == status.HTTP_200_OK
    assert response.text == '"Index of the User Management Service"'


def test_get_from_some_other_path(client):
    """Test that a GET request to a random path raises a not found error."""

    response = client.post("/some/path")

    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_post_claim(client_with_db):
    """Test that posting a user claim works."""

    user_dao = DummyUserDao()
    client_with_db.app.dependency_overrides[get_user_dao] = lambda: user_dao

    response = client_with_db.post("/users/john@ghga.org/claims", json=CLAIM_DATA)

    claim = response.json()
    assert response.status_code == status.HTTP_201_CREATED, claim

    claim_id = claim.pop("id", None)
    assert claim_id is not None
    assert len(claim_id) == 36
    assert claim_id.count("-") == 4
    assert claim.pop("sub_source") is None
    assert claim.pop("asserted_by") is None
    assert claim.pop("conditions") is None
    assert claim.pop("revocation_date") is None
    assert claim.pop("revocation_by") is None
    assert claim.pop("creation_date") is not None
    assert claim.pop("creation_by") is not None

    assert claim == CLAIM_DATA
