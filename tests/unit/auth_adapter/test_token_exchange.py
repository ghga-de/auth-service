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
#

"""Unit tests for the auth adapter core token exchange feature"""

from ghga_service_chassis_lib.utils import now_as_utc
from pytest import mark, raises

from auth_service.auth_adapter.core import auth
from auth_service.user_management.user_registry.models.dto import UserStatus

from ...fixtures.utils import (
    DummyClaimDao,
    DummyUserDao,
    create_access_token,
    get_claims_from_token,
)


@mark.asyncio
async def test_rejects_an_expired_access_token():
    """Test the token exchange for a user with an expired token."""
    access_token = create_access_token(expired=True)
    with raises(auth.TokenValidationError, match="Not a valid token: Expired"):
        await auth.exchange_token(access_token)


@mark.asyncio
async def test_exchanges_token_for_unknown_user_if_requested():
    """Test token exchange for a valid but unknown user with pass_sub flag."""
    access_token = create_access_token()
    user_dao = DummyUserDao(ls_id="not.john@aai.org")
    internal_token = await auth.exchange_token(
        access_token, pass_sub=True, user_dao=user_dao
    )
    assert internal_token is not None
    claims = get_claims_from_token(internal_token)
    assert isinstance(claims, dict)
    expected_claims = {"email", "name", "ls_id", "exp", "iat"}
    assert set(claims) == expected_claims
    assert claims["name"] == "John Doe"
    assert claims["email"] == "john@home.org"
    assert claims["ls_id"] == "john@aai.org"
    assert isinstance(claims["iat"], int)
    assert isinstance(claims["exp"], int)
    assert claims["iat"] <= int(now_as_utc().timestamp()) < claims["exp"]


@mark.asyncio
async def test_does_not_exchange_for_unknown_user_if_not_requested():
    """Test token exchange for a valid but unknown user without pass_sub flag."""
    access_token = create_access_token()
    user_dao = DummyUserDao(ls_id="not.john@aai.org")
    assert await auth.exchange_token(access_token, user_dao=user_dao) is None


@mark.asyncio
async def test_exchanges_access_token_for_a_known_user():
    """Test the token exchange for a valid and already known user."""
    access_token = create_access_token()
    user_dao, claim_dao = DummyUserDao(), DummyClaimDao()
    internal_token = await auth.exchange_token(
        access_token, user_dao=user_dao, claim_dao=claim_dao
    )
    assert internal_token is not None
    claims = get_claims_from_token(internal_token)
    assert isinstance(claims, dict)
    expected_claims = {"email", "name", "id", "status", "exp", "iat"}
    assert set(claims) == expected_claims
    assert claims["name"] == "John Doe"
    assert claims["email"] == "john@home.org"
    assert claims["id"] == "john@ghga.de"
    assert claims["status"] == "activated"
    assert isinstance(claims["iat"], int)
    assert isinstance(claims["exp"], int)
    assert claims["iat"] <= int(now_as_utc().timestamp()) < claims["exp"]
    assert user_dao.user.status is UserStatus.ACTIVATED
    assert user_dao.user.status_change is None


@mark.asyncio
async def test_also_passes_sub_for_a_known_user():
    """Test that the sub claim is also passed for an already known user."""
    access_token = create_access_token()
    user_dao, claim_dao = DummyUserDao(), DummyClaimDao()
    internal_token = await auth.exchange_token(
        access_token, pass_sub=True, user_dao=user_dao, claim_dao=claim_dao
    )
    assert internal_token is not None
    claims = get_claims_from_token(internal_token)
    assert isinstance(claims, dict)
    assert claims["id"] == "john@ghga.de"
    assert claims["ls_id"] == "john@aai.org"


@mark.asyncio
async def test_exchanges_access_token_when_name_was_changed():
    """Test the token exchange for a valid user with a different name."""
    access_token = create_access_token()
    user_dao = DummyUserDao(name="John Foo")
    internal_token = await auth.exchange_token(access_token, user_dao=user_dao)
    assert internal_token is not None
    claims = get_claims_from_token(internal_token)
    assert isinstance(claims, dict)
    expected_claims = {"email", "name", "id", "status", "exp", "iat"}
    assert set(claims) == expected_claims
    assert claims["name"] == "John Doe"
    assert claims["email"] == "john@home.org"
    assert claims["id"] == "john@ghga.de"
    assert claims["status"] == "inactivated"
    assert isinstance(claims["iat"], int)
    assert isinstance(claims["exp"], int)
    assert claims["iat"] <= int(now_as_utc().timestamp()) < claims["exp"]
    status_change = user_dao.user.status_change
    assert status_change is not None
    assert status_change.previous is UserStatus.ACTIVATED
    assert status_change.by is None
    assert status_change.context == "name changed"
    assert 0 <= (now_as_utc() - status_change.change_date).total_seconds() < 5


@mark.asyncio
async def test_exchanges_access_token_when_email_was_changed():
    """Test the token exchange for a valid user with a different email."""
    access_token = create_access_token()
    user_dao = DummyUserDao(email="john@elsewhere.org")
    internal_token = await auth.exchange_token(access_token, user_dao=user_dao)
    assert internal_token is not None
    claims = get_claims_from_token(internal_token)
    assert isinstance(claims, dict)
    expected_claims = {"email", "name", "id", "status", "exp", "iat"}
    assert set(claims) == expected_claims
    assert claims["name"] == "John Doe"
    assert claims["email"] == "john@home.org"
    assert claims["id"] == "john@ghga.de"
    assert claims["status"] == "inactivated"
    assert isinstance(claims["iat"], int)
    assert isinstance(claims["exp"], int)
    assert claims["iat"] <= int(now_as_utc().timestamp()) < claims["exp"]
    status_change = user_dao.user.status_change
    assert status_change is not None
    assert status_change.previous is UserStatus.ACTIVATED
    assert status_change.by is None
    assert status_change.context == "email changed"
    assert 0 <= (now_as_utc() - status_change.change_date).total_seconds() < 5


@mark.asyncio
async def test_adds_role_for_a_known_data_steward():
    """Test that the internal token contains the role for a data steward."""
    access_token = create_access_token()
    user_dao, claim_dao = (DummyUserDao(id_="james@ghga.de"), DummyClaimDao())
    internal_token = await auth.exchange_token(
        access_token, user_dao=user_dao, claim_dao=claim_dao
    )
    assert internal_token is not None
    claims = get_claims_from_token(internal_token)
    assert isinstance(claims, dict)
    expected_claims = {"email", "name", "id", "status", "exp", "iat", "role"}
    assert set(claims) == expected_claims
    assert claims["id"] == "james@ghga.de"
    assert claims["status"] == "activated"

    assert claims["role"] == "data_steward"
