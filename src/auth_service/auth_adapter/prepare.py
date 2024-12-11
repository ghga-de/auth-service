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

"""Prepare the auth adapter by providing all dependencies"""

from fastapi import FastAPI
from ghga_service_commons.api import configure_app
from hexkit.providers.mongodb import MongoDbDaoFactory

from ..config import Config
from . import DESCRIPTION, TITLE, VERSION, deps
from .adapters.memory_session_store import MemorySessionStore
from .api.basic import add_basic_auth_exception_handler
from .api.router import router
from .core.totp import TOTPHandler
from .translators.dao import UserTokenDaoFactory

__all__ = ["prepare_rest_app"]


async def prepare_rest_app(*, config: Config) -> FastAPI:
    """Construct and initialize the REST API app along with all its dependencies."""
    app = FastAPI(title=TITLE, description=DESCRIPTION, version=VERSION)
    configure_app(app, config=config)
    add_basic_auth_exception_handler(app, config)
    app.include_router(router)

    session_store = MemorySessionStore(config=config)
    totp_handler = TOTPHandler(config=config)

    mongodb_dao_facory = MongoDbDaoFactory(config=config)
    user_token_dao_factory = UserTokenDaoFactory(
        config=config, dao_factory=mongodb_dao_facory
    )
    user_token_dao = await user_token_dao_factory.get_user_token_dao()

    app.dependency_overrides[deps.get_session_store] = lambda: session_store
    app.dependency_overrides[deps.get_totp_handler] = lambda: totp_handler
    app.dependency_overrides[deps.get_user_token_dao] = lambda: user_token_dao

    return app
