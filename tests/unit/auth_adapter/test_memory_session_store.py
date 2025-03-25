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
#

"""Unit tests for the memory session store."""

from datetime import timedelta

import pytest
from ghga_service_commons.utils.utc_dates import UTCDatetime, utc_datetime

from auth_service.auth_adapter.adapters.memory_session_store import MemorySessionStore
from auth_service.auth_adapter.core.session_store import Session, SessionConfig

USER_KWARGS = dict(
    ext_id="john@aai.org", user_name="John Doe", user_email="john@home.org"
)
USER2_KWARGS = dict(
    ext_id="jane@aai.org", user_name="Jane Roe", user_email="jane@home.org"
)

pytestmark = pytest.mark.asyncio(loop_scope="module")


class MemorySessionStoreWithControlledTime(MemorySessionStore):
    """A memory session store with a fixed session creation time."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.now = utc_datetime(2024, 12, 24, 12, 24, 48)

    def _now(self) -> UTCDatetime:
        """Get a fixed time for testing."""
        return self.now

    def sleep(self, seconds: int = 10) -> None:
        """Pretend that a given number of seconds has passed."""
        self.now += timedelta(seconds=seconds)


class MemorySessionStoreWithBadIdGenerator(MemorySessionStore):
    """A memory session store with a bad session ID generator."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.next_session_id = 1

    def _generate_session_id(self) -> str:
        """Generate a session ID with repeated values."""
        current_session_id = self.next_session_id
        self.next_session_id = (current_session_id + 1) % 3 + 1
        return f"id{current_session_id}"


@pytest.fixture
def store():
    """Get a new memory session store for testing."""
    return MemorySessionStoreWithControlledTime(config=SessionConfig())


async def test_create_session(store):
    """Test creating a session."""
    session = await store.create_session(**USER_KWARGS)
    assert await store.get_size() == 1
    assert isinstance(session, Session)
    assert session.session_id
    assert isinstance(session.session_id, str)
    assert len(session.session_id) == store.config.session_id_bytes * 4 // 3
    assert session.created == session.last_used


async def test_create_session_with_session_id(store):
    """Test that a session cannot be created with a given session ID."""
    with pytest.raises(ValueError):
        await store.create_session(session_id="some-session-id", **USER_KWARGS)


async def test_create_session_with_bad_generator():
    """Test saving a session with a bad session generator."""
    bad_store = MemorySessionStoreWithBadIdGenerator(config=SessionConfig())
    for i in range(3):
        session = await bad_store.create_session(**USER_KWARGS)
        assert await bad_store.get_size() == i + 1
        assert isinstance(session, Session)
        assert session.session_id.startswith("id")
        assert session.created == session.last_used

    with pytest.raises(RuntimeError, match="Could not create a new session"):
        session = await bad_store.create_session(**USER_KWARGS)
    assert await bad_store.get_size() == 3


async def test_save_session(store):
    """Test saving a session."""
    session = store._create_session(**USER_KWARGS)
    await store.save_session(session)
    assert session.ext_id == USER_KWARGS["ext_id"]
    assert session.user_name == USER_KWARGS["user_name"]
    assert session.user_email == USER_KWARGS["user_email"]
    assert session.user_id is None
    assert session.created == store.now
    assert session.last_used == store.now
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is session


async def test_update_session(store):
    """Test updating a session."""
    session = await store.create_session(**USER_KWARGS)
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is session
    assert session.ext_id == "john@aai.org"
    session = session.model_copy(update={"user_email": "john@elsewhere.org"})
    await store.save_session(session)
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is session
    assert session.user_email == "john@elsewhere.org"


async def test_get_session(store):
    """Test getting a session."""
    session = await store.create_session(**USER_KWARGS)
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is session


async def test_get_invalid_session(store):
    """Test getting an invalid session."""
    session = await store.create_session(**USER_KWARGS)
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is session
    session.created -= timedelta(
        seconds=1.5 * store.config.session_max_lifetime_seconds
    )
    assert await store.get_session(session.session_id) is None
    assert await store.get_size() == 0


async def test_delete_session(store):
    """Test deleting a session."""
    session = await store.create_session(**USER_KWARGS)
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is not None
    await store.delete_session(session.session_id)
    assert await store.get_size() == 0
    assert await store.get_session(session.session_id) is None
    await store.delete_session(session.session_id)
    assert await store.get_size() == 0
    assert await store.get_session(session.session_id) is None


async def test_crud_two_sessions(store):
    """Test creating, getting, updating and deleting two different sessions."""
    session1 = await store.create_session(**USER_KWARGS)
    session2 = await store.create_session(**USER2_KWARGS)
    assert await store.get_size() == 2
    assert await store.get_session(session1.session_id) is session1
    assert await store.get_session(session2.session_id) is session2
    session3 = session2.model_copy(update={"user_name": "Johanna Roe"})
    await store.save_session(session3)
    assert await store.get_size() == 2
    assert await store.get_session(session1.session_id) is session1
    assert await store.get_session(session2.session_id) is session3
    await store.delete_session(session2.session_id)
    assert await store.get_size() == 1
    assert await store.get_session(session1.session_id) is session1
    assert await store.get_session(session2.session_id) is None
    await store.delete_session(session1.session_id)
    assert await store.get_size() == 0
    assert await store.get_session(session1.session_id) is None
    assert await store.get_session(session2.session_id) is None


async def test_get_size(store):
    """Test determining the size of the session store."""
    assert await store.get_size() == 0
    for i in range(10):
        await store.create_session(
            ext_id="john@aai.org", user_name="John Doe", user_email="john@home.org"
        )
        assert await store.get_size() == i + 1


async def test_session_sweeper(store):
    """Test sweeping the session store."""
    sessions = [
        await store.create_session(
            ext_id="john@aai.org", user_name="John Doe", user_email="john@home.org"
        )
        for _ in range(10)
    ]
    assert await store.get_size() == 10
    await store.sweep()
    assert await store.get_size() == 10
    long_time = timedelta(seconds=1.5 * store.config.session_max_lifetime_seconds)
    for i, session in enumerate(sessions):
        if i % 2:
            session.created -= long_time
        await store.save_session(session)
    await store.sweep()
    assert await store.get_size() == 5
    await store.sweep()
    assert await store.get_size() == 5
    for session in sessions:
        session.created -= long_time
        await store.save_session(session)
    await store.sweep()
    assert await store.get_size() == 0
    await store.sweep()
    assert await store.get_size() == 0
