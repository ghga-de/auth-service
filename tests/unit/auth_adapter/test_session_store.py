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

"""Test the core user session store functionality."""

from datetime import timedelta
from typing import Any

import pytest
from ghga_service_commons.utils.utc_dates import UTCDatetime, utc_datetime

from auth_service.auth_adapter.core.session_store import (
    Session,
    SessionConfig,
    SessionState,
    SessionStore,
)
from auth_service.user_management.claims_repository.core.claims import Role
from auth_service.user_management.user_registry.models.users import (
    AcademicTitle,
    User,
    UserStatus,
)

pytestmark = pytest.mark.asyncio(loop_scope="module")


class CoreSessionStore(SessionStore):
    """A core user session store for testing."""

    def _now(self) -> UTCDatetime:
        """Get a fixed for testing."""
        return utc_datetime(2024, 12, 24, 12, 24, 48)

    async def create_session(self, **kwargs: Any) -> Session:
        """Create a new user session in the store and return it."""
        raise NotImplementedError

    async def save_session(self, session: Session, **kwargs: Any) -> None:
        """Save an existing user session back to the store."""
        await self._update_session(session, **kwargs)
        self.saved_session = session

    async def get_session(self, session_id: str) -> Session | None:
        """Get a valid user session with a given ID."""
        raise NotImplementedError

    async def delete_session(self, session_id: str) -> None:
        """Delete a user session with a given ID.

        If no such user session exists, do nothing.
        """
        raise NotImplementedError

    async def get_size(self) -> int:
        """Get the number of currently stored sessions."""
        raise NotImplementedError

    async def sweep(self) -> None:
        """Remove all invalid sessions from the store."""
        raise NotImplementedError


async def test_create_session():
    """Test generation of sessions."""
    config = SessionConfig()
    session_id_bytes = config.session_id_bytes
    assert session_id_bytes >= 16
    session_id_length = session_id_bytes * 4 // 3  # because of base64 encoding
    csrf_token_bytes = config.csrf_token_bytes
    assert csrf_token_bytes >= 16
    csrf_token_length = csrf_token_bytes * 4 // 3
    store = CoreSessionStore(config=config)
    now = store._now()
    create_session = store._create_session
    session_ids = []
    csrf_tokens = []
    for _ in range(100):
        session = create_session(
            ext_id="john@aai.org", user_name="John Doe", user_email="john@home.org"
        )
        assert isinstance(session, Session)
        session_id = session.session_id
        assert isinstance(session_id, str)
        assert len(session_id) == session_id_length
        assert session_id.replace("-", "").replace("_", "").isalnum()
        csrf_token = session.csrf_token
        assert isinstance(csrf_token, str)
        assert len(csrf_token) == csrf_token_length
        # check that the session ID contains only URL safe characters
        assert csrf_token.replace("-", "").replace("_", "").isalnum()
        session_ids.append(session_id)
        csrf_tokens.append(csrf_token)
        assert session.ext_id == "john@aai.org"
        assert session.user_name == "John Doe"
        assert session.user_email == "john@home.org"
        assert session.user_id is None
        assert session.created == now
        assert session.last_used == now
    # make sure that no duplicate session IDs are created
    session_id_set = set(session_ids)
    assert len(session_id_set) == len(session_ids)
    # make sure that different CSRF tokens are created
    csrf_token_set = set(csrf_tokens)
    assert len(csrf_token_set) >= len(csrf_tokens) * 0.75
    # make sure that they are different from the session IDs
    assert len(session_id_set & csrf_token_set) < len(session_ids) * 0.25


async def test_validate_session():
    """Test validation of sessions."""
    config = SessionConfig()
    timeout_seconds = config.session_timeout_seconds
    max_lifetime_seconds = config.session_max_lifetime_seconds
    store = CoreSessionStore(config=config)
    validate = store._validate_session
    create_session = store._create_session
    session = create_session(
        ext_id="john@aai.lorg", user_name="John Doe", user_email="john@home.org"
    )

    now = store._now()
    assert validate(session)

    session.created = now - timedelta(seconds=1.5 * max_lifetime_seconds)
    assert not validate(session)
    session.created = now - timedelta(seconds=0.5 * max_lifetime_seconds)
    assert validate(session)
    session.last_used = now - timedelta(seconds=1.5 * timeout_seconds)
    assert not validate(session)

    session.created = session.last_used = now - timedelta(seconds=1)
    assert validate(session)
    session.created = session.last_used = now + timedelta(seconds=1)
    assert not validate(session)


@pytest.mark.parametrize(
    "original_state",
    [
        SessionState.NEEDS_REGISTRATION,
        SessionState.NEEDS_RE_REGISTRATION,
        SessionState.REGISTERED,
        SessionState.HAS_TOTP_TOKEN,
    ],
)
async def test_update_session_last_used_without_user(original_state: SessionState):
    """Test updating a session without user object, should not update state."""
    config = SessionConfig()
    store = CoreSessionStore(config=config)
    now = store._now()
    before = now - timedelta(seconds=10)
    session = Session(
        session_id="test",
        state=original_state,
        ext_id="john@aai.org",
        user_name="John Doe",
        user_email="john@home.org",
        csrf_token="some-csrf-token",
        created=before,
        last_used=before,
    )
    await store.save_session(session)
    assert store.saved_session is session
    assert session.state == original_state
    assert session.created == before
    assert session.last_used == now


@pytest.mark.parametrize("changed_field", ["name", "email"])
async def test_update_session_with_user_to_needs_re_registration(changed_field: str):
    """Test updating a session to the needs-re-registration state."""
    config = SessionConfig()
    store = CoreSessionStore(config=config)
    now = store._now()
    before = now - timedelta(seconds=10)
    session = Session(
        session_id="test",
        ext_id="john@aai.org",
        user_name="John Doe",
        user_email="john@home.org",
        csrf_token="some-csrf-token",
        created=before,
        last_used=before,
    )
    assert session.user_id is None
    assert session.state is SessionState.NEEDS_REGISTRATION
    user = User(
        id="some-user-id",
        ext_id="john@aai.org",
        name="John Doe",
        email="john@home.org",
        status=UserStatus.ACTIVE,
        registration_date=before,
    )
    changed_value = getattr(user, changed_field).replace("ohn", "oe")
    user = user.model_copy(update={changed_field: changed_value})
    await store.save_session(session, user=user)
    assert store.saved_session is session
    assert session.created == before
    assert session.last_used == now
    assert session.user_id == "some-user-id"
    assert session.state is SessionState.NEEDS_RE_REGISTRATION


@pytest.mark.parametrize(
    "original_state",
    [
        SessionState.NEEDS_REGISTRATION,
        SessionState.NEEDS_RE_REGISTRATION,
        SessionState.REGISTERED,
    ],
)
async def test_update_session_with_user_to_registered(original_state: SessionState):
    """Test updating a session to the registered state."""
    config = SessionConfig()
    store = CoreSessionStore(config=config)
    now = store._now()
    before = now - timedelta(seconds=10)
    session = Session(
        session_id="test",
        state=original_state,
        ext_id="some-ext-id@home.org",
        user_id=None
        if original_state is SessionState.NEEDS_REGISTRATION
        else "some-user-id",
        user_name="John Doe",
        user_email="john@home.org",
        csrf_token="some-csrf-token",
        created=before,
        last_used=before,
    )
    user = User(
        id="some-user-id",
        ext_id="some-ext-id@home.org",
        name="John Doe",
        email="john@home.org",
        status=UserStatus.ACTIVE,
        registration_date=before,
    )
    await store.save_session(session, user=user)
    assert store.saved_session is session
    assert session.created == before
    assert session.last_used == now
    assert session.user_id == "some-user-id"
    assert session.user_name == "John Doe"
    assert session.user_title is None
    assert session.roles == []
    assert session.state is SessionState.REGISTERED


@pytest.mark.parametrize(
    "original_state",
    [
        SessionState.NEEDS_REGISTRATION,
        SessionState.NEEDS_RE_REGISTRATION,
        SessionState.REGISTERED,
    ],
)
async def test_update_session_with_data_steward_to_registered(
    original_state: SessionState,
):
    """Test updating a session to the registered state with data steward role."""
    config = SessionConfig()
    store = CoreSessionStore(config=config)
    now = store._now()
    before = now - timedelta(seconds=10)
    session = Session(
        session_id="test",
        state=original_state,
        ext_id="some-ext-id@home.org",
        user_id=None
        if original_state is SessionState.NEEDS_REGISTRATION
        else "some-user-id",
        user_name="John Doe",
        user_email="john@home.org",
        csrf_token="some-csrf-token",
        created=before,
        last_used=before,
    )
    user = User(
        id="some-user-id",
        ext_id="some-ext-id@home.org",
        name="John Doe",
        title=AcademicTitle.DR,
        email="john@home.org",
        status=UserStatus.ACTIVE,
        registration_date=before,
    )

    async def _get_roles(user: User) -> list[Role]:
        return [Role.DATA_STEWARD]

    await store.save_session(session, user=user, get_roles=_get_roles)
    assert store.saved_session is session
    assert session.created == before
    assert session.last_used == now
    assert session.user_id == "some-user-id"
    assert session.user_name == "John Doe"
    if original_state is not SessionState.REGISTERED:
        assert session.user_title == "Dr."
        assert session.roles == ["data_steward"]
    assert session.state is SessionState.REGISTERED


@pytest.mark.parametrize(
    "original_state",
    [
        SessionState.NEEDS_REGISTRATION,
        SessionState.NEEDS_RE_REGISTRATION,
        SessionState.REGISTERED,
        SessionState.HAS_TOTP_TOKEN,
    ],
)
async def test_update_session_with_user_to_has_totp_token(original_state: SessionState):
    """Test updating a session to the has-totp-state."""
    config = SessionConfig()
    store = CoreSessionStore(config=config)
    now = store._now()
    before = now - timedelta(seconds=10)
    session = Session(
        session_id="test",
        state=original_state,
        ext_id="some-ext-id@home.org",
        user_id=None
        if original_state is SessionState.NEEDS_REGISTRATION
        else "some-user-id",
        user_name="John Doe",
        user_email="john@home.org",
        csrf_token="some-csrf-token",
        created=before,
        last_used=before,
    )
    user = User(
        id="some-user-id",
        ext_id="some-ext-id@home.org",
        name="John Doe",
        email="john@home.org",
        status=UserStatus.ACTIVE,
        registration_date=before,
    )

    async def _has_totp_token(user: User) -> bool:
        return True

    await store.save_session(session, user=user, has_totp_token=_has_totp_token)
    assert store.saved_session is session
    assert session.created == before
    assert session.last_used == now
    assert session.user_id == "some-user-id"
    assert session.state is SessionState.HAS_TOTP_TOKEN


async def test_timeouts():
    """Test getting the session timeouts."""
    config = SessionConfig()
    store = CoreSessionStore(config=config)
    now = store._now()
    session = Session(
        session_id="test",
        ext_id="john@aai.org",
        user_name="John Doe",
        user_email="john@home.org",
        csrf_token="some-csrf-token",
        created=now - timedelta(seconds=2 * 60 * 60),
        last_used=now - timedelta(seconds=20 * 60),
    )
    assert store.timeouts(session) == (40 * 60, 10 * 60 * 60)
    session.created = now - timedelta(seconds=12 * 60 * 60 - 10 * 60)
    assert store.timeouts(session) == (10 * 60, 10 * 60)
