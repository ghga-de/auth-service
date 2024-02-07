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

from auth_service.deps import Depends, get_config

from .adapters.memory_session_store import MemorySessionStore
from .core.session_store import Session, SessionConfig
from .ports.session_store import SessionStorePort

__all__ = ["get_session_store"]


def get_session_store(
    config: SessionConfig = Depends(get_config),
) -> SessionStorePort[Session]:
    """Get the session store."""
    return MemorySessionStore(config=config)
