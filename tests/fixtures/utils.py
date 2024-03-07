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

"""Utils for testing"""

import json
import re
from collections.abc import AsyncIterator, Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional, Union

from fastapi import Request
from ghga_service_commons.api import ApiConfigBase
from ghga_service_commons.utils.utc_dates import now_as_utc, utc_datetime
from hexkit.config import config_from_yaml
from hexkit.protocols.dao import NoHitsFoundError, ResourceNotFoundError
from jwcrypto import jwk, jwt

from auth_service.auth_adapter.core.session_store import Session
from auth_service.auth_adapter.ports.dao import UserToken
from auth_service.config import CONFIG
from auth_service.user_management.claims_repository.models.claims import (
    AuthorityLevel,
    Claim,
    VisaType,
)
from auth_service.user_management.user_registry.models.ivas import Iva
from auth_service.user_management.user_registry.models.users import User, UserData

BASE_DIR = Path(__file__).parent.resolve()

RE_USER_INFO_URL = re.compile(".*/userinfo$")

USER_INFO = {
    "name": "John Doe",
    "email": "john@home.org",
    "sub": "john@aai.org",
}


@config_from_yaml(prefix="test_auth_service")
class AdditionalConfig(ApiConfigBase):
    """Config that holds private keys for testing.

    Should be set as additional environment variables when running the test.
    """

    # full internal key for user management and auth adapter
    auth_key: str
    # full external key set for auth adapter
    auth_ext_keys: Optional[str] = None


class SigningKeys:
    """Signing keys that can be used for testing."""

    internal_jwk: jwk.JWK
    external_jwk: Optional[jwk.JWK]

    def __init__(self):
        config = AdditionalConfig()  # pyright: ignore
        self.internal_jwk = jwk.JWK.from_json(config.auth_key)
        self.external_jwk = (
            jwk.JWKSet.from_json(config.auth_ext_keys).get_key("test")
            if config.auth_ext_keys
            else None
        )


signing_keys = SigningKeys()


def create_access_token(
    key: Optional[jwk.JWK] = None,
    expired: bool = False,
    **kwargs: Union[None, int, str],
) -> str:
    """Create an external access token that can be used for testing.

    If no signing key is provided, the additional test configuration is used.
    """
    if not key:
        key = signing_keys.external_jwk
    assert isinstance(key, jwk.JWK)
    kty = key["kty"]
    assert kty in ("EC", "RSA")
    header = {"alg": "ES256" if kty == "EC" else "RS256", "typ": "JWT"}
    claims: dict[str, Union[None, str, int]] = {
        "jti": "123-456-789-0",
        "sub": "john@aai.org",
        "iss": str(CONFIG.oidc_authority_url).rstrip("/"),
        "client_id": CONFIG.oidc_client_id,
        "foo": "bar",
        "token_class": "access_token",
    }
    iat = int(now_as_utc().timestamp())
    if expired:
        exp = iat - 60 * 10  # expired 10 minutes ago
        iat = exp - 60 * 10  # created 20 minutes ago
    else:
        exp = iat + 60 * 10  # valid for 10 minutes
    claims.update(iat=iat, exp=exp)
    claims.update(kwargs)
    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    access_token = token.serialize()
    assert token and isinstance(access_token, str)
    assert len(access_token) > 50
    assert access_token.count(".") == 2
    return access_token


def create_internal_token(
    key: Optional[jwk.JWK] = None,
    expired: bool = False,
    **kwargs: Union[None, int, str],
) -> str:
    """Create an internal token that can be used for testing.

    If no signing key is provided, the additional test configuration is used.
    """
    if key is None:
        key = signing_keys.internal_jwk
    assert isinstance(key, jwk.JWK)
    kty = key["kty"]
    assert kty in ("EC", "RSA")
    header = {"alg": "ES256" if kty == "EC" else "RS256", "typ": "JWT"}
    claims: dict[str, Union[None, int, str]] = {
        "name": "John Doe",
        "email": "john@home.org",
        "status": "active",
    }
    iat = int(now_as_utc().timestamp())
    if expired:
        exp = iat - 60 * 10  # expired 10 minutes ago
        iat = exp - 60 * 10  # created 20 minutes ago
    else:
        exp = iat + 60 * 30  # valid for 30 minutes
    claims.update(iat=iat, exp=exp)
    claims.update(kwargs)
    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    internal_token = token.serialize()
    assert token and isinstance(internal_token, str)
    assert len(internal_token) > 50
    assert internal_token.count(".") == 2
    return internal_token


def get_headers_for(
    key: Optional[jwk.JWK] = None,
    expired: bool = False,
    **kwargs: Union[None, int, str],
) -> dict[str, str]:
    """Create the headers for an internal token with the given arguments.

    If no signing key is provided, the additional test configuration is used.
    """
    token = create_internal_token(key=key, expired=expired, **kwargs)
    return {"Authorization": f"Bearer {token}"}


def get_claims_from_token(token: str, key: Optional[jwk.JWK] = None) -> dict[str, Any]:
    """Decode the given JWT access token and get its claims.

    If no signing key is provided, the additional test configuration is used.
    """
    if key is None:
        key = signing_keys.internal_jwk
    assert isinstance(key, jwk.JWK)
    assert token and isinstance(token, str)
    assert len(token) > 50
    assert token.count(".") == 2
    claims = json.loads(jwt.JWT(jwt=token, key=key).claims)
    assert isinstance(claims, dict)
    return claims


def headers_for_session(session: Session) -> dict[str, str]:
    """Get proper headers for the given session."""
    return {
        "X-CSRF-Token": session.csrf_token,
        "Cookie": f"session={session.session_id}",
    }


def request_with_authorization(token: str = "") -> Request:
    """Get a dummy request with the given bearer token in the authorization header."""
    authorization = f"Bearer {token}".encode("ascii")
    return Request({"type": "http", "headers": [(b"authorization", authorization)]})


class DummyUserDao:
    """UserDao that can retrieve one dummy user."""

    user: User

    def __init__(
        self,
        id_="john@ghga.de",
        name="John Doe",
        email="john@home.org",
        title=None,
        ext_id="john@aai.org",
        status="active",
    ):
        """Initialize the dummy UserDao"""
        self.user = User(
            id=id_,
            name=name,
            email=email,  # pyright: ignore
            title=title,
            ext_id=ext_id,  # pyright: ignore
            status=status,  # pyright: ignore
            status_change=None,
            registration_date=utc_datetime(2020, 1, 1),
            active_submissions=[],
            active_access_requests=[],
        )

    async def get_by_id(self, id_: str) -> User:
        """Get the dummy user via internal ID."""
        if id_ == self.user.id:
            return self.user
        raise ResourceNotFoundError(id_=id_)

    async def find_one(self, *, mapping: Mapping[str, Any]) -> Optional[User]:
        """Find the dummy user via LS-ID."""
        user, ext_id = self.user, mapping.get("ext_id")
        if user and ext_id and ext_id == user.ext_id:
            return user
        raise NoHitsFoundError(mapping=mapping)

    async def insert(self, user: UserData) -> User:
        """Insert the dummy user."""
        user = User(id=user.ext_id.replace("@aai.org", "@ghga.de"), **user.model_dump())
        self.user = user
        return user

    async def update(self, user: User) -> None:
        """Update the dummy user."""
        if user.id == self.user.id:
            self.user = user

    async def delete(self, id_: str) -> None:
        """Update the dummy user."""
        if id_ != self.user.id:
            raise ResourceNotFoundError(id_=id_)
        self.user = self.user.model_copy(update={"id": "deleted"})


class DummyIvaDao:
    """UserDao that can retrieve one dummy IVA."""

    ivas: list[Iva]

    def __init__(self, ivas: Optional[list[Iva]] = None):
        """Initialize the dummy UserDao"""
        self.ivas = ivas if ivas else []

    async def find_all(self, *, mapping: Mapping[str, Any]) -> AsyncIterator[Iva]:
        """Find all dummy IVAs."""
        mapping = json.loads(json.dumps(mapping))
        for iva in self.ivas:
            data = iva.model_dump()
            data["id_"] = data.pop("id")
            for key in mapping:
                if mapping[key] != data[key]:
                    break
            else:
                yield iva


class DummyUserTokenDao:
    """Dummy UserTokenDao for testing."""

    user_tokens: dict[str, UserToken]

    def __init__(self):
        """Initialize the dummy UserTokenDao"""
        self.user_tokens = {}

    async def get_by_id(self, id_: str) -> UserToken:
        """Get the user token via the ID."""
        try:
            return self.user_tokens[id_]
        except KeyError as error:
            raise ResourceNotFoundError(id_=id_) from error

    async def update(self, dto: UserToken) -> None:
        """Update a user token."""
        self.user_tokens[dto.user_id] = dto

    async def upsert(self, dto: UserToken) -> None:
        """Upsert a user token."""
        self.user_tokens[dto.user_id] = dto


class DummyClaimDao:
    """ClaimDao that can retrieve a dummy data steward claim."""

    claims: list[Claim]

    def __init__(self, valid_date=now_as_utc()):
        """Initialize the dummy ClaimDao"""
        self.valid_date = valid_date
        self.invalid_date = valid_date + timedelta(14)
        self.claims = [
            Claim(
                id="data-steward-claim-id",
                user_id="james@ghga.de",
                visa_type=VisaType.GHGA_ROLE,
                visa_value="data_steward@some.org",
                source="https://ghga.de",  # type: ignore
                assertion_date=valid_date - timedelta(14),
                asserted_by=AuthorityLevel.SYSTEM,
                valid_from=valid_date - timedelta(7),
                valid_until=valid_date + timedelta(7),
                creation_date=valid_date - timedelta(10),
            ),
            Claim(
                id="data-access-claim-id",
                user_id="john@ghga.de",
                visa_type=VisaType.CONTROLLED_ACCESS_GRANTS,
                visa_value="https://ghga.de/datasets/some-dataset-id",
                source="https://ghga.de",  # type: ignore
                assertion_date=valid_date - timedelta(14),
                asserted_by=AuthorityLevel.DAC,
                valid_from=valid_date - timedelta(7),
                valid_until=valid_date + timedelta(7),
                creation_date=valid_date - timedelta(10),
            ),
        ]

    async def get_by_id(self, id_: str) -> Claim:
        """Get a dummy user claim via its ID."""
        for claim in self.claims:
            if claim.id == id_:
                return claim
        raise ResourceNotFoundError(id_=id_)

    async def find_all(self, *, mapping: Mapping[str, Any]) -> AsyncIterator[Claim]:
        """Find all dummy user claims."""
        mapping = json.loads(json.dumps(mapping))
        for claim in self.claims:
            data = claim.model_dump()
            data["id_"] = data.pop("id")
            for key in mapping:
                if mapping[key] != data[key]:
                    break
            else:
                yield claim

    async def delete(self, *, id_: str) -> None:
        """Delete a dummy user claim."""
        claim = await self.get_by_id(id_)
        self.claims.remove(claim)
