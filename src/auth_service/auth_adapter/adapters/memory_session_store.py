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

"""An adapter for a memory based session store."""

import asyncio
from contextlib import suppress
from typing import Callable, Generic, Optional, TypeVar

from auth_service.auth_adapter.ports.session_store import BaseSession, SessionStorePort

T = TypeVar("T", bound=BaseSession)


class MemorySessionStore(SessionStorePort, Generic[T]):
    """Memory based store for user sessions."""

    def __init__(self, *, creator: Callable[[], T], validator: Callable[[T], bool]):
        """Create a session store.

        Functions for creating and validating sessions must be provided.
        """
        super().__init__(creator=creator, validator=validator)
        self.lock = asyncio.Lock()
        self.store: dict[str, T] = {}

    async def create_session(self) -> T:
        """Create a new user session in the store and return it."""
        for _ in range(100):
            async with self.lock:
                session = self.creator()
                # avoid overwrite an existing session
                if session.session_id not in self.store:
                    self.store[session.session_id] = session
                    return session
            await asyncio.sleep(0)
        # this should never happen with a good session creator
        raise RuntimeError("Could not create a new session.")

    async def save_session(self, session: T) -> None:
        """Save an existing user session back to the store."""
        self.store[session.session_id] = session

    async def get_session(self, user_id: str) -> Optional[T]:
        """Get a valid user session with a given ID.

        If no such user session exists, return None.
        If it exists but is invalid, remove it from the store and return None.
        """
        async with self.lock:
            session = self.store.get(user_id)
            if session and not self.validator(session):
                await self.delete_session(session.session_id)
                session = None
        return session

    async def delete_session(self, session_id: str) -> None:
        """Delete a user session with a given ID.

        If no such user session exists, do nothing.
        """
        with suppress(KeyError):
            del self.store[session_id]

    async def get_size(self) -> int:
        """Get the number of currently stored sessions."""
        return len(self.store)

    async def sweep(self) -> None:
        """Remove all invalid sessions from the store."""
        session_ids = list(self.store)
        validator = self.validator
        get_session = self.get_session
        sleep = asyncio.sleep
        for session_id in session_ids:
            session = await get_session(session_id)
            if session and not validator(session):
                await self.delete_session(session_id)
            await sleep(0)
