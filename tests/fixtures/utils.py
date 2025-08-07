# Copyright 2021 - 2025 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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
from contextlib import suppress
from datetime import timedelta
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from fastapi import Request
from ghga_service_commons.api import ApiConfigBase
from ghga_service_commons.utils.utc_dates import UTCDatetime, utc_datetime
from hexkit.config import config_from_yaml
from hexkit.protocols.dao import (
    Dao,
    MultipleHitsFoundError,
    NoHitsFoundError,
    ResourceNotFoundError,
)
from hexkit.utils import now_utc_ms_prec
from jwcrypto import jwk, jwt
from pydantic import UUID4

from auth_service.auth_adapter.core.session_store import Session
from auth_service.auth_adapter.ports.dao import UserToken
from auth_service.claims_repository.models.claims import (
    AuthorityLevel,
    Claim,
    VisaType,
)
from auth_service.config import CONFIG
from auth_service.user_registry.core.registry import (
    ClaimDto,
    DaoPublisher,
    IvaDto,
    UserDto,
    UserRegistry,
    UserRegistryConfig,
)
from auth_service.user_registry.models.ivas import (
    Iva,
    IvaState,
    IvaType,
)
from auth_service.user_registry.models.users import User
from auth_service.user_registry.ports.event_pub import (
    EventPublisherPort,
)
from tests.fixtures.constants import (
    DATA_ACCESS_CLAIM_ID,
    DATA_ACCESS_IVA_ID,
    DATA_STEWARD_CLAIM_ID,
    DATA_STEWARD_IVA_ID,
    EXT_ID_OF_JOHN,
    EXT_TO_INT_ID,
    ID_OF_JAMES,
    ID_OF_JOHN,
    IVA_IDS,
)

BASE_DIR = Path(__file__).parent.resolve()

RE_USER_INFO_URL = re.compile(".*/userinfo$")

USER_INFO = {
    "name": "John Doe",
    "email": "john@home.org",
    "sub": EXT_ID_OF_JOHN,
}


@config_from_yaml(prefix="test_auth_service")
class AdditionalConfig(ApiConfigBase):
    """Config that holds private keys for testing.

    Should be set as additional environment variables when running the test.
    """

    # full internal key for auth service and auth adapter
    auth_key: str
    # full external key set for auth adapter
    auth_ext_keys: str | None = None


class SigningKeys:
    """Signing keys that can be used for testing."""

    internal_jwk: jwk.JWK
    external_jwk: jwk.JWK | None

    def __init__(self):
        config = AdditionalConfig()  # type: ignore
        self.internal_jwk = jwk.JWK.from_json(config.auth_key)
        self.external_jwk = (
            jwk.JWKSet.from_json(config.auth_ext_keys).get_key("test")
            if config.auth_ext_keys
            else None
        )


signing_keys = SigningKeys()


def create_access_token(
    key: jwk.JWK | None = None,
    expired: bool = False,
    **kwargs: None | int | str,
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
    claims: dict[str, None | str | int] = {
        "jti": "123-456-789-0",
        "sub": EXT_ID_OF_JOHN,
        "iss": str(CONFIG.oidc_authority_url),
        "client_id": CONFIG.oidc_client_id,
        "foo": "bar",
        "aud": CONFIG.oidc_client_id,
        "scope": "openid email profile",
    }
    iat = int(now_utc_ms_prec().timestamp())
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
    key: jwk.JWK | None = None,
    expired: bool = False,
    **kwargs: Any,
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
    claims: dict[str, Any] = {
        "name": "John Doe",
        "email": "john@home.org",
        "status": "active",
    }
    iat = int(now_utc_ms_prec().timestamp())
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
    key: jwk.JWK | None = None,
    expired: bool = False,
    **kwargs: Any,
) -> dict[str, str]:
    """Create the headers for an internal token with the given arguments.

    If no signing key is provided, the additional test configuration is used.
    """
    token = create_internal_token(key=key, expired=expired, **kwargs)
    return {"Authorization": f"Bearer {token}"}


def get_claims_from_token(token: str, key: jwk.JWK | None = None) -> dict[str, Any]:
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

    users: list[User]

    def __init__(
        self,
        id_=ID_OF_JOHN,
        name="John Doe",
        email="john@home.org",
        title=None,
        ext_id=EXT_ID_OF_JOHN,
        status="active",
    ):
        """Initialize the DummyUserDao."""
        self.users = [
            User(
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
        ]

    @property
    def user(self) -> User:
        """Get the last inserted user."""
        return self.users[-1]

    async def get_by_id(self, id_: UUID4) -> User:
        """Get the dummy user via internal ID."""
        for user in self.users:
            if id_ == user.id:
                return user
        raise ResourceNotFoundError(id_=id_)

    async def find_one(self, *, mapping: Mapping[str, Any]) -> User:
        """Find the dummy user via LS-ID."""
        mapping = json.loads(json.dumps(mapping, default=str))
        ext_id = mapping.get("ext_id")
        for user in self.users:
            if not ext_id or ext_id == user.ext_id:
                return user
        raise NoHitsFoundError(mapping=mapping)

    async def find_all(self, *, mapping: Mapping[str, Any]) -> AsyncIterator[User]:
        """Find all dummy users with given ID(s)."""
        mapping = json.loads(json.dumps(mapping, default=str))
        for user in self.users:
            data = user.model_dump()
            for key, value in mapping.items():
                if isinstance(value, dict) and "$in" in value:
                    # mock the MongoDB "$in" operator
                    if data[key] not in value["$in"]:
                        break
                elif data[key] != value:
                    break
            else:
                yield user

    async def insert(self, dto: User) -> None:
        """Insert the dummy user."""
        dto = dto.model_copy(update={"id": EXT_TO_INT_ID[dto.ext_id]})
        user = User(**dto.model_dump())
        self.users.append(user)

    async def update(self, dto: User) -> None:
        """Update the dummy user."""
        for index, user in enumerate(self.users):
            if dto.id == user.id:
                self.users[index] = dto
                break
        else:
            raise ResourceNotFoundError(id_=dto.id)

    async def delete(self, id_: UUID4) -> None:
        """Delete the dummy user."""
        for index, user in enumerate(self.users):
            if id_ == user.id:
                del self.users[index]
                break
        else:
            raise ResourceNotFoundError(id_=id_)


class DummyIvaDao:
    """UserDao that can retrieve one dummy IVA."""

    ivas: list[Iva]

    def __init__(self, ivas: list[Iva] | None = None, state=IvaState.VERIFIED):
        """Initialize the DummyIvaDao."""
        if ivas is None:
            now = now_utc_ms_prec()
            ivas = [
                Iva(
                    id=DATA_STEWARD_IVA_ID,
                    user_id=ID_OF_JAMES,
                    value="Nice to meet you",
                    type=IvaType.IN_PERSON,
                    state=state,
                    created=now,
                    changed=now,
                ),
                Iva(
                    id=DATA_STEWARD_IVA_ID,
                    user_id=ID_OF_JOHN,
                    value="123/456",
                    type=IvaType.PHONE,
                    state=state,
                    created=now,
                    changed=now,
                ),
            ]
        self.ivas = ivas

    async def get_by_id(self, id_: UUID4) -> Iva:
        """Get a dummy IVA via its ID."""
        for iva in self.ivas:
            if iva.id == id_:
                return iva
        raise ResourceNotFoundError(id_=id_)

    async def find_all(self, *, mapping: Mapping[str, Any]) -> AsyncIterator[Iva]:
        """Find all dummy IVAs."""
        mapping = json.loads(json.dumps(mapping, default=str))
        for iva in self.ivas:
            data = iva.model_dump()
            for key, value in mapping.items():
                if isinstance(value, dict) and "$in" in value:
                    # mock the MongoDB "$in" operator
                    if data[key] not in value["$in"]:
                        break
                elif data[key] != value:
                    break
            else:
                yield iva

    async def insert(self, dto: Iva) -> None:
        """Insert a dummy IVA."""
        dto = Iva(**dto.model_dump())
        self.ivas.append(dto)

    async def update(self, dto: Iva) -> None:
        """Update a dummy IVA."""
        iva_id = dto.id
        for index, iva in enumerate(self.ivas):
            if iva.id == iva_id:
                self.ivas[index] = dto
                break
        else:
            raise ResourceNotFoundError(id_=iva_id)

    async def delete(self, id_: UUID4) -> None:
        """Delete a dummy IVA."""
        iva = await self.get_by_id(id_)
        self.ivas.remove(iva)


class DummyUserTokenDao:
    """Dummy UserTokenDao for testing."""

    user_tokens: dict[str, UserToken]

    def __init__(self):
        """Initialize the dummy UserTokenDao"""
        self.user_tokens = {}

    async def get_by_id(self, id_: str) -> UserToken:
        """Get the user token via the (user) ID."""
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

    def __init__(self, valid_date=now_utc_ms_prec()):
        """Initialize the DummyClaimDao."""
        self.valid_date = valid_date
        self.invalid_date = valid_date + timedelta(14)
        self.claims = [
            Claim(
                id=DATA_STEWARD_CLAIM_ID,
                user_id=ID_OF_JAMES,
                iva_id=DATA_STEWARD_IVA_ID,
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
                id=DATA_ACCESS_CLAIM_ID,
                user_id=ID_OF_JOHN,
                iva_id=DATA_ACCESS_IVA_ID,
                visa_type=VisaType.CONTROLLED_ACCESS_GRANTS,
                visa_value="https://ghga.de/datasets/DS0815",
                source="https://ghga.de",  # type: ignore
                assertion_date=valid_date - timedelta(14),
                asserted_by=AuthorityLevel.DAC,
                valid_from=valid_date - timedelta(7),
                valid_until=valid_date + timedelta(7),
                creation_date=valid_date - timedelta(10),
            ),
        ]

    async def get_by_id(self, id_: UUID4) -> Claim:
        """Get a dummy user claim via its ID."""
        for claim in self.claims:
            if claim.id == id_:
                return claim
        raise ResourceNotFoundError(id_=id_)

    async def find_one(self, *, mapping: Mapping[str, Any]) -> Claim:
        """Find a dummy user claim."""
        claims = []
        async for claim in self.find_all(mapping=mapping):
            claims.append(claim)
        if not claims:
            raise NoHitsFoundError(mapping=mapping)
        if len(claims) > 1:
            raise MultipleHitsFoundError(mapping=mapping)
        return claims[0]

    async def find_all(self, *, mapping: Mapping[str, Any]) -> AsyncIterator[Claim]:
        """Find all dummy user claims."""
        mapping = json.loads(json.dumps(mapping, default=str))
        for claim in self.claims:
            data = claim.model_dump()
            data["id_"] = data.pop("id")
            for key, value in mapping.items():
                if isinstance(value, dict) and "$in" in value:
                    # mock the MongoDB "$in" operator
                    if data[key] not in value["$in"]:
                        break
                elif data[key] != value:
                    break

            else:
                yield claim

    async def update(self, dto: Claim) -> None:
        """Update a dummy user claim."""
        for index, claim in enumerate(self.claims):
            if claim.id == dto.id:
                self.claims[index] = dto
                break
        else:
            raise ResourceNotFoundError(id_=dto.id)

    async def insert(self, dto: Claim) -> None:
        """Insert a dummy user claim."""
        claim = Claim(**dto.model_dump())
        self.claims.append(claim)

    async def delete(self, id_: UUID4) -> None:
        """Delete a dummy user claim."""
        claim = await self.get_by_id(id_)
        self.claims.remove(claim)


class DummyEventPublisher(EventPublisherPort):
    """User registry event publisher for testing."""

    def __init__(self):
        """Initialize the dummy event publisher."""
        self.published_events = []

    async def publish_2fa_recreated(self, *, user_id: UUID4) -> None:
        """Publish an event relaying that the 2nd factor of a user was recreated."""
        self.published_events.append(("2fa_recreation", user_id))

    async def publish_iva_state_changed(self, *, iva: Iva) -> None:
        """Publish an event relaying that the state of a user IVA has been changed."""
        self.published_events.append(("iva_state_changed", iva))

    async def publish_ivas_reset(self, *, user_id: UUID4) -> None:
        """Publish an event relaying that all IVAs of the user have been reset."""
        self.published_events.append(("ivas_reset", user_id))


class DummyUserRegistry(UserRegistry):
    """A modified user registry for testing with the dummy DAOs."""

    published_events: list[tuple[str, Any]]

    def __init__(self, *, config: UserRegistryConfig = CONFIG):
        """Initialize the DummyUserRegistry."""
        self.dummy_user_dao = DummyUserDao()
        self.dummy_iva_dao = DummyIvaDao([])
        self._dummy_claim_dao = DummyClaimDao()
        event_publisher = DummyEventPublisher()
        super().__init__(
            config=config,
            user_dao=cast(DaoPublisher[UserDto], self.dummy_user_dao),
            iva_dao=cast(DaoPublisher[IvaDto], self.dummy_iva_dao),
            claim_dao=cast(Dao[ClaimDto], self._dummy_claim_dao),
            event_pub=event_publisher,
        )
        self.published_events = event_publisher.published_events

    @staticmethod
    def is_internal_user_id(id_: str) -> bool:
        """Check if the passed ID is an internal user id."""
        with suppress(ValueError, TypeError):
            converted_id = UUID(id_)
            return converted_id.version == 4
        return False

    @staticmethod
    def is_external_user_id(id_: str) -> bool:
        """Check if the passed ID is an external user id."""
        return isinstance(id_, str) and id_.endswith("@aai.org")

    @property
    def dummy_user(self) -> User:
        """Get the dummy user."""
        return self.dummy_user_dao.user

    @property
    def dummy_users(self) -> list[User]:
        """Get the dummy users."""
        return self.dummy_user_dao.users

    @property
    def dummy_ivas(self) -> list[Iva]:
        """Get the dummy IVAs."""
        return self.dummy_iva_dao.ivas

    def add_dummy_iva(
        self,
        id_: UUID4 | None = None,
        user_id: UUID4 | None = None,
        type_: IvaType = IvaType.PHONE,
        value: str = "123456",
        state: IvaState = IvaState.UNVERIFIED,
        verification_code_hash: str | None = None,
        verification_attempts: int = 0,
        created: UTCDatetime | None = None,
        changed: UTCDatetime | None = None,
    ):
        """Add a dummy IVA with the specified data."""
        self.dummy_ivas.append(
            Iva(
                id=id_ or IVA_IDS[len(self.dummy_ivas)],
                state=state,
                type=type_,
                value=value,
                user_id=user_id or self.dummy_user.id,
                verification_code_hash=verification_code_hash,
                verification_attempts=verification_attempts,
                created=created or now_utc_ms_prec(),
                changed=changed or now_utc_ms_prec(),
            )
        )
