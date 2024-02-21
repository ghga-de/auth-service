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

"""FastAPI dependencies for the auth adapter"""

from typing import Annotated, Optional

from fastapi import Cookie

from auth_service.deps import Depends, get_config

from .adapters.memory_session_store import MemorySessionStore
from .core.session_store import Session, SessionConfig
from .core.totp import TOTPConfig, TOTPHandler, TOTPToken
from .ports.session_store import SessionStorePort
from .ports.totp import TOTPHandlerPort

__all__ = [
    "get_session_store",
    "get_session",
    "SessionStoreDependency",
    "SessionDependency",
]

_session_store = None
_totp_handler = None


async def get_session_store(
    config: Annotated[SessionConfig, Depends(get_config)],
) -> SessionStorePort[Session]:
    """Get the session store."""
    global _session_store
    if not _session_store:
        _session_store = MemorySessionStore(config=config)
    return _session_store


async def get_session(
    store: Annotated[SessionStorePort[Session], Depends(get_session_store)],
    session: Annotated[Optional[str], Cookie()] = None,
) -> Optional[Session]:
    """Get the current session."""
    return await store.get_session(session) if session else None


async def get_totp_handler(
    config: Annotated[TOTPConfig, Depends(get_config)],
) -> TOTPHandlerPort[TOTPToken]:
    """Get the TOTP handler."""
    global _totp_handler
    if not _totp_handler:
        _totp_handler = TOTPHandler(config=config)
    return _totp_handler


SessionStoreDependency = Annotated[
    SessionStorePort[Session], Depends(get_session_store)
]

SessionDependency = Annotated[Optional[Session], Depends(get_session)]

TOTPHandlerDependency = Annotated[TOTPHandlerPort[TOTPToken], Depends(get_totp_handler)]
