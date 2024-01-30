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

"""Unit tests for the memory session store."""

from pytest import fixture, mark, raises

from auth_service.auth_adapter.adapters.memory_session_store import MemorySessionStore
from auth_service.auth_adapter.ports.session_store import BaseSession


class Session(BaseSession):
    """A user session for testing."""

    name: str


session_counter = 0


def session_creator() -> Session:
    """A session creator for testing."""
    global session_counter
    session_counter += 1
    return Session(session_id=str(session_counter), name="new")


def session_validator(session) -> bool:
    """A session validator for testing."""
    return session.name != "invalid"


bad_session_counter = 0


def bad_session_creator() -> Session:
    """A session creator for testing that repeats session IDs."""
    global bad_session_counter
    bad_session_counter = (bad_session_counter + 1) % 3
    return Session(session_id=f"id{bad_session_counter}", name="bad")


@fixture
def store():
    """Get a new memory session store for testing."""
    return MemorySessionStore[Session](
        creator=session_creator, validator=session_validator
    )


@mark.asyncio
async def test_create_session(store):
    """Test saving a session."""
    session = await store.create_session()
    assert await store.get_size() == 1
    assert isinstance(session, Session)
    assert session.session_id.isdigit()
    assert session.name == "new"


@mark.asyncio
async def test_create_session_with_bad_generator():
    """Test saving a session with a bad session generator."""
    bad_store = MemorySessionStore[Session](
        creator=bad_session_creator, validator=session_validator
    )
    for i in range(3):
        session = await bad_store.create_session()
        assert await bad_store.get_size() == i + 1
        assert isinstance(session, Session)
        assert session.session_id.startswith("id")
        assert session.name == "bad"
    with raises(RuntimeError, match="Could not create a new session"):
        session = await bad_store.create_session()
    assert await bad_store.get_size() == 3


@mark.asyncio
async def test_save_session(store):
    """Test saving a session."""
    session = session_creator()
    await store.save_session(session)
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is session


@mark.asyncio
async def test_update_session(store):
    """Test updating a session."""
    session = await store.create_session()
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is session
    assert session.name == "new"
    session = session.model_copy(update={"name": "updated"})
    await store.save_session(session)
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is session


@mark.asyncio
async def test_get_session(store):
    """Test getting a session."""
    session = await store.create_session()
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is session


@mark.asyncio
async def test_get_invalid_session(store):
    """Test getting an invalid session."""
    session = await store.create_session()
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is session
    assert session.name == "new"
    session.name = "invalid"
    assert await store.get_session(session.session_id) is None
    assert await store.get_size() == 0


@mark.asyncio
async def test_delete_session(store):
    """Test deleting a session."""
    session = await store.create_session()
    assert await store.get_size() == 1
    assert await store.get_session(session.session_id) is not None
    await store.delete_session(session.session_id)
    assert await store.get_size() == 0
    assert await store.get_session(session.session_id) is None
    await store.delete_session(session.session_id)
    assert await store.get_size() == 0
    assert await store.get_session(session.session_id) is None


@mark.asyncio
async def test_crud_two_sessions(store):
    """Test creating, getting, updating and deleting two different sessions."""
    session1 = await store.create_session()
    session2 = await store.create_session()
    assert await store.get_size() == 2
    assert await store.get_session(session1.session_id) is session1
    assert await store.get_session(session2.session_id) is session2
    session3 = session2.model_copy(update={"name": "updated"})
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


@mark.asyncio
async def test_get_size(store):
    """Test determining the size of the session store."""
    assert await store.get_size() == 0
    for i in range(10):
        await store.create_session()
        assert await store.get_size() == i + 1


@mark.asyncio
async def test_session_sweeper(store):
    """Test sweeping the session store."""
    sessions = [await store.create_session() for _ in range(10)]
    assert await store.get_size() == 10
    await store.sweep()
    assert await store.get_size() == 10
    for i, session in enumerate(sessions):
        session.name = "invalid" if i % 2 else "valid"
        await store.save_session(session)
    await store.sweep()
    assert await store.get_size() == 5
    await store.sweep()
    assert await store.get_size() == 5
    for session in sessions:
        session.name = "invalid"
        await store.save_session(session)
    await store.sweep()
    assert await store.get_size() == 0
    await store.sweep()
    assert await store.get_size() == 0
