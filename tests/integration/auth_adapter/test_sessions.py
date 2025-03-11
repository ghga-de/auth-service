# Copyright 2021 - 2024 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

"""Test handling user sessions in the auth adapter."""

import json
from base64 import b64encode
from collections.abc import Mapping
from typing import Any

import pytest
from fastapi import FastAPI, status
from httpx import Response
from pytest_httpx import HTTPXMock

from auth_service.auth_adapter.deps import (
    SESSION_COOKIE,
    get_session_store,
    get_user_token_dao,
)
from auth_service.user_management.claims_repository.deps import get_claim_dao
from auth_service.user_management.user_registry.deps import get_iva_dao, get_user_dao
from auth_service.user_management.user_registry.models.users import UserStatus

from ...fixtures.utils import (
    RE_USER_INFO_URL,
    USER_INFO,
    DummyClaimDao,
    DummyIvaDao,
    DummyUserDao,
    DummyUserTokenDao,
    IvaState,
    create_access_token,
    headers_for_session,
)
from .fixtures import (
    AUTH_PATH,
    BareClient,
    ClientWithBasicAuth,
    fixture_bare_client,  # noqa: F401
    fixture_bare_client_with_basic_auth,  # noqa: F401
)

pytestmark = pytest.mark.asyncio()


LOGIN_PATH = AUTH_PATH + "/rpc/login"
LOGOUT_PATH = AUTH_PATH + "/rpc/logout"


def expected_set_cookie(session_id: str) -> str:
    """Get the expected Set-Cookie header for the auth session cookie."""
    return f"session={session_id}; HttpOnly; Path=/; SameSite=lax; Secure"


def setup_daos(
    app: FastAPI,
    iva_state: IvaState = IvaState.VERIFIED,
    **user_args: str,
) -> None:
    """Setup the dummy DAOs for the tests."""
    user_dao = DummyUserDao(**user_args)
    app.dependency_overrides[get_user_dao] = lambda: user_dao
    user_token_dao = DummyUserTokenDao()
    app.dependency_overrides[get_user_token_dao] = lambda: user_token_dao
    iva_dao = DummyIvaDao(state=iva_state)
    app.dependency_overrides[get_iva_dao] = lambda: iva_dao
    claim_dao = DummyClaimDao()
    app.dependency_overrides[get_claim_dao] = lambda: claim_dao


def assert_session_header(response: Response, expected: Mapping[str, Any]) -> None:
    """Assert that the response session header is as expected."""
    session_header = response.headers.get("X-Session")
    assert session_header
    session = json.loads(session_header)
    assert isinstance(session, dict)
    csrf_token = session.pop("csrf", None)
    assert len(csrf_token) == 32
    assert csrf_token.replace("-", "").replace("_", "").isalnum()
    timeout = session.pop("timeout", None)
    assert isinstance(timeout, int)
    assert timeout == 60 * 60
    extends = session.pop("extends", None)
    assert isinstance(extends, int)
    assert extends == 12 * 60 * 60
    assert session == expected


async def test_logout(bare_client: BareClient):
    """Test that a logout request removes the user session."""
    store = bare_client.app.dependency_overrides[get_session_store]()
    session = await store.create_session(
        ext_id="john@aai.org", user_name="John Doe", user_email="john@home.org"
    )
    assert await store.get_session(session.session_id)
    headers = headers_for_session(session)
    response = await bare_client.post(LOGOUT_PATH, headers=headers)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not await store.get_session(session.session_id)

    cookie = response.headers.get("Set-Cookie")
    assert cookie
    assert "expires=" in cookie
    assert "Max-Age=0" in cookie
    cookie = ";".join(
        filter(
            lambda part: not part.startswith(" expires=") and part != " Max-Age=0",
            cookie.split(";"),
        )
    )
    assert cookie == expected_set_cookie('""')

    assert SESSION_COOKIE not in response.cookies
    assert "X-Session" not in response.headers


async def test_logout_without_session(bare_client: BareClient):
    """Test that a logout request without a session does not fail."""
    response = await bare_client.post(LOGOUT_PATH)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    assert SESSION_COOKIE not in response.cookies
    assert "Set-Cookie" not in response.headers
    assert "X-Session" not in response.headers


async def test_logout_with_invalid_csrf_token(bare_client: BareClient):
    """Test that a logout request with an invalid CSRF token fails."""
    store = bare_client.app.dependency_overrides[get_session_store]()
    session = await store.create_session(
        ext_id="john@aai.org", user_name="John Doe", user_email="john@home.org"
    )
    original_session = session.model_copy()
    headers = headers_for_session(session)
    headers["X-CSRF-Token"] += "-invalidated"
    assert await store.get_session(session.session_id)
    response = await bare_client.post(LOGOUT_PATH, headers=headers)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert "X-CSRF-Token" not in response.headers
    assert response.json() == {"detail": "Invalid or missing CSRF token"}
    assert await store.get_session(session.session_id) == original_session

    assert SESSION_COOKIE not in response.cookies
    assert "Set-Cookie" not in response.headers
    assert "X-Session" not in response.headers


async def test_login_with_unregistered_user(
    bare_client: BareClient, httpx_mock: HTTPXMock
):
    """Test that a login request can create a new session for an unregistered user."""
    httpx_mock.add_response(url=RE_USER_INFO_URL, json=USER_INFO)

    setup_daos(bare_client.app, ext_id="not.john@aai.org")

    auth = f"Bearer {create_access_token()}"
    response = await bare_client.post(LOGIN_PATH, headers={"Authorization": auth})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    session_id = response.cookies.get(SESSION_COOKIE)
    assert session_id
    store = bare_client.app.dependency_overrides[get_session_store]()
    session = await store.get_session(session_id)
    assert session
    assert response.cookies.get(SESSION_COOKIE) == session_id
    assert response.headers.get("Set-Cookie") == expected_set_cookie(session_id)
    assert_session_header(
        response,
        {
            "ext_id": "john@aai.org",
            "name": "John Doe",
            "email": "john@home.org",
            "state": "NeedsRegistration",
            "roles": [],
        },
    )


async def test_login_with_invalid_userinfo(
    bare_client: BareClient, httpx_mock: HTTPXMock
):
    """Test that a login request fails when user info cannot be retrieved."""
    bad_user_info = {**USER_INFO, "sub": "not.john@aai.org"}
    httpx_mock.add_response(url=RE_USER_INFO_URL, json=bad_user_info)

    setup_daos(bare_client.app, ext_id="not.john@aai.org")

    auth = f"Bearer {create_access_token()}"
    response = await bare_client.post(LOGIN_PATH, headers={"Authorization": auth})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {
        "detail": "Subject in userinfo differs from access token"
    }

    assert SESSION_COOKIE not in response.cookies
    assert "X-Session" not in response.headers


async def test_login_with_registered_user(
    bare_client: BareClient, httpx_mock: HTTPXMock
):
    """Test that a login request can create a new session for a registered user."""
    httpx_mock.add_response(url=RE_USER_INFO_URL, json=USER_INFO)

    setup_daos(bare_client.app)

    auth = f"Bearer {create_access_token()}"
    response = await bare_client.post(LOGIN_PATH, headers={"Authorization": auth})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    session_id = response.cookies.get(SESSION_COOKIE)
    assert session_id
    store = bare_client.app.dependency_overrides[get_session_store]()
    session = await store.get_session(session_id)
    assert session
    assert response.cookies.get(SESSION_COOKIE) == session_id
    assert response.headers.get("Set-Cookie") == expected_set_cookie(session_id)
    assert_session_header(
        response,
        {
            "id": "john@ghga.de",
            "ext_id": "john@aai.org",
            "name": "John Doe",
            "email": "john@home.org",
            "state": "Registered",
            "roles": [],
        },
    )


async def test_login_with_registered_user_and_name_change(
    bare_client: BareClient, httpx_mock: HTTPXMock
):
    """Test a login request for a user when the name was changed."""
    changed_user_info = {**USER_INFO, "name": "John Doe Jr."}
    httpx_mock.add_response(url=RE_USER_INFO_URL, json=changed_user_info)

    setup_daos(bare_client.app)

    auth = f"Bearer {create_access_token()}"
    response = await bare_client.post(LOGIN_PATH, headers={"Authorization": auth})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    session_id = response.cookies.get(SESSION_COOKIE)
    assert session_id
    store = bare_client.app.dependency_overrides[get_session_store]()
    session = await store.get_session(session_id)
    assert session
    assert response.cookies.get(SESSION_COOKIE) == session_id
    assert response.headers.get("Set-Cookie") == expected_set_cookie(session_id)
    assert_session_header(
        response,
        {
            "id": "john@ghga.de",
            "ext_id": "john@aai.org",
            "name": "John Doe Jr.",
            "email": "john@home.org",
            "state": "NeedsReRegistration",
            "roles": [],
        },
    )


async def test_login_with_registered_user_with_title(
    bare_client: BareClient, httpx_mock: HTTPXMock
):
    """Test a login request for a user when a title was entered."""
    httpx_mock.add_response(url=RE_USER_INFO_URL, json=USER_INFO)

    setup_daos(bare_client.app, title="Dr.")

    auth = f"Bearer {create_access_token()}"
    response = await bare_client.post(LOGIN_PATH, headers={"Authorization": auth})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    session_id = response.cookies.get(SESSION_COOKIE)
    assert session_id
    store = bare_client.app.dependency_overrides[get_session_store]()
    session = await store.get_session(session_id)
    assert session
    assert response.cookies.get(SESSION_COOKIE) == session_id
    assert response.headers.get("Set-Cookie") == expected_set_cookie(session_id)
    assert_session_header(
        response,
        {
            "id": "john@ghga.de",
            "ext_id": "john@aai.org",
            "name": "John Doe",
            "email": "john@home.org",
            "title": "Dr.",
            "state": "Registered",
            "roles": [],
        },
    )


async def test_login_with_deactivated_user(
    bare_client: BareClient, httpx_mock: HTTPXMock
):
    """Test that a login request for a registered deactivated user fails."""
    httpx_mock.add_response(url=RE_USER_INFO_URL, json=USER_INFO)

    setup_daos(bare_client.app, status=UserStatus.INACTIVE)

    auth = f"Bearer {create_access_token()}"
    response = await bare_client.post(LOGIN_PATH, headers={"Authorization": auth})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {"detail": "User account is disabled"}


async def test_login_without_access_token(bare_client: BareClient):
    """Test that a login request without an access token fails."""
    response = await bare_client.post(LOGIN_PATH)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {"detail": "No access token provided"}

    assert SESSION_COOKIE not in response.cookies
    assert "X-Session" not in response.headers


async def test_login_without_access_token_and_basic_auth(
    client_with_basic_auth: ClientWithBasicAuth,
):
    """Test login request with valid basic auth but without access token."""
    bare_client, credentials = client_with_basic_auth

    auth = b64encode(credentials.encode("UTF-8")).decode("ASCII")
    auth = f"Basic {auth}"
    response = await bare_client.post(LOGIN_PATH, headers={"Authorization": auth})
    # should give a 403 instead of 401 to distinguish from basic access error
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.json() == {"detail": "No access token provided"}

    assert SESSION_COOKIE not in response.cookies
    assert "X-Session" not in response.headers
    assert "WWW-Authenticate" not in response.headers


async def test_login_with_invalid_access_token(bare_client: BareClient):
    """Test that a login request with an invalid access token fails."""
    auth = "Bearer invalid"
    response = await bare_client.post(LOGIN_PATH, headers={"Authorization": auth})
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json() == {
        "detail": "Access token error: Not a valid token: Token format unrecognized"
    }

    assert SESSION_COOKIE not in response.cookies
    assert "X-Session" not in response.headers


async def test_login_with_cookie_and_unregistered_user(bare_client: BareClient):
    """Test login request with session cookie for an unregistered user."""
    setup_daos(bare_client.app, ext_id="not.john@aai.org")

    store = bare_client.app.dependency_overrides[get_session_store]()
    session = await store.create_session(
        ext_id="john@aai.org", user_name="John Doe", user_email="john@home.org"
    )
    assert await store.get_session(session.session_id)
    headers = headers_for_session(session)
    response = await bare_client.post(LOGIN_PATH, headers=headers)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    assert SESSION_COOKIE not in response.cookies
    assert_session_header(
        response,
        {
            "ext_id": "john@aai.org",
            "name": "John Doe",
            "email": "john@home.org",
            "state": "NeedsRegistration",
            "roles": [],
        },
    )


async def test_login_with_cookie_and_registered_user(bare_client: BareClient):
    """Test login request with session cookie for a registered user."""
    setup_daos(bare_client.app)

    store = bare_client.app.dependency_overrides[get_session_store]()
    session = await store.create_session(
        ext_id="john@aai.org",
        user_id="john@ghga.de",
        user_name="John Doe",
        user_email="john@home.org",
    )
    assert await store.get_session(session.session_id)
    headers = headers_for_session(session)
    response = await bare_client.post(LOGIN_PATH, headers=headers)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    assert SESSION_COOKIE not in response.cookies
    assert_session_header(
        response,
        {
            "id": "john@ghga.de",
            "ext_id": "john@aai.org",
            "name": "John Doe",
            "email": "john@home.org",
            "state": "Registered",
            "roles": [],
        },
    )


@pytest.mark.parametrize("iva_state", IvaState)
async def test_login_with_cookie_and_registered_data_steward(
    iva_state: IvaState, bare_client: BareClient
):
    """Test login request with session cookie for a registered data steward."""
    setup_daos(
        bare_client.app,
        id_="james@ghga.de",
        ext_id="james@aai.org",
        name="James Steward",
        email="james@home.org",
        title="Dr.",
        iva_state=iva_state,
    )

    store = bare_client.app.dependency_overrides[get_session_store]()
    session = await store.create_session(
        ext_id="james@aai.org",
        user_id="james@ghga.de",
        user_name="James Steward",
        user_email="james@home.org",
    )
    assert await store.get_session(session.session_id)
    headers = headers_for_session(session)
    response = await bare_client.post(LOGIN_PATH, headers=headers)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    assert SESSION_COOKIE not in response.cookies
    expected_session_header: dict[str, Any] = {
        "id": "james@ghga.de",
        "ext_id": "james@aai.org",
        "name": "James Steward",
        "email": "james@home.org",
        "state": "Registered",
        "title": "Dr.",
    }
    expected_session_header["roles"] = (
        ["data_steward"] if iva_state == IvaState.VERIFIED else []
    )
    assert_session_header(response, expected_session_header)


async def test_login_with_cookie_but_without_csrf_token(bare_client: BareClient):
    """Test login request with session cookie but no CSRF token.

    It should be possible to login from a new browser tab using the session cookie.
    """
    setup_daos(bare_client.app)

    store = bare_client.app.dependency_overrides[get_session_store]()
    session = await store.create_session(
        ext_id="john@aai.org",
        user_id="john@ghga.de",
        user_name="John Doe",
        user_email="john@home.org",
    )
    assert await store.get_session(session.session_id)
    headers = headers_for_session(session)
    del headers["X-CSRF-Token"]
    response = await bare_client.post(LOGIN_PATH, headers=headers)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    assert SESSION_COOKIE not in response.cookies
    assert_session_header(
        response,
        {
            "id": "john@ghga.de",
            "ext_id": "john@aai.org",
            "name": "John Doe",
            "email": "john@home.org",
            "state": "Registered",
            "roles": [],
        },
    )
