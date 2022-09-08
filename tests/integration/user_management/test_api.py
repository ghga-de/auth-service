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

"""Test the api module"""

from fastapi import status

from auth_service.user_management.core.utils import is_internal_id

from .fixtures import (  # noqa: F401; pylint: disable=unused-import
    fixture_client,
    fixture_client_with_db,
)

FULL_USER_DATA = dict(
    ls_id="max@ls.org",
    status="activated",
    name="Max Headroom",
    title="Dr.",
    email="max@example.org",
    research_topics="genes",
    registration_reason="for testing",
    registration_date="2022-09-01T12:00:00",
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


def test_post_user(client_with_db):
    """Test that registering a user works."""

    user_data = FULL_USER_DATA
    response = client_with_db.post("/users", json=user_data)

    user = response.json()
    assert response.status_code == status.HTTP_201_CREATED, user

    id_ = user.pop("id", None)
    assert is_internal_id(id_)

    assert user == user_data

    response = client_with_db.post("/users", json=user_data)

    error = response.json()
    assert response.status_code == status.HTTP_409_CONFLICT, error
    assert error == {"detail": "User was already registered."}


def test_get_non_existing_user(client_with_db):
    """Test requesting a non-existing user."""

    response = client_with_db.get("/users/bad@example.org")

    error = response.json()
    assert response.status_code == status.HTTP_404_NOT_FOUND, error
    assert error == {"detail": "The user was not found."}


def test_get_user_via_id(client_with_db):
    """Test that a registered user can be found via internal ID."""

    user_data = FULL_USER_DATA
    response = client_with_db.post("/users", json=user_data)
    expected_user = response.json()
    assert response.status_code == status.HTTP_201_CREATED

    id_ = expected_user["id"]
    response = client_with_db.get(f"/users/{id_}")

    user = response.json()
    assert response.status_code == status.HTTP_200_OK, user

    assert user == expected_user


def test_get_user_via_ls_id(client_with_db):
    """Test that a registered user can be found via LS ID."""

    user_data = FULL_USER_DATA
    response = client_with_db.post("/users", json=user_data)
    expected_user = response.json()
    assert response.status_code == status.HTTP_201_CREATED

    id_ = expected_user["ls_id"]
    response = client_with_db.get(f"/users/{id_}")

    user = response.json()
    assert response.status_code == status.HTTP_200_OK, user

    assert user == expected_user
