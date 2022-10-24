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

"""Fixtures for the auth adapter integration tests"""

import importlib
from typing import Generator

from fastapi.testclient import TestClient
from pytest import fixture
from testcontainers.mongodb import MongoDbContainer

from auth_service.auth_adapter.api import main
from auth_service.config import Config
from auth_service.deps import (
    UserDaoFactory,
    get_config,
    get_mongodb_config,
    get_mongodb_dao_factory,
    get_user_dao_factory,
    get_user_dao_factory_config,
)


@fixture(name="client")
def fixture_client() -> TestClient:
    """Get test client for the auth adapter"""
    return TestClient(main.app)


@fixture(name="client_with_db")
def fixture_client_with_db() -> Generator[
    tuple[TestClient, UserDaoFactory], None, None
]:
    """Get test client for the auth adapter with a test database."""

    with MongoDbContainer() as mongodb:
        connection_url = mongodb.get_connection_url()
        config = Config(db_url=connection_url, db_name="test-auth-adapter")

        user_dao_factory = get_user_dao_factory(
            config=get_user_dao_factory_config(config=config),
            dao_factory=get_mongodb_dao_factory(
                config=get_mongodb_config(config=config)
            ),
        )

        main.app.dependency_overrides[get_config] = lambda: config
        yield TestClient(main.app), user_dao_factory


@fixture(name="with_basic_auth")
def fixture_with_basic_auth() -> Generator[str, None, None]:
    """Run test with Basic authentication"""
    user, pwd = "testuser", "testpwd"
    config = get_config()
    config.basic_auth_user = user
    config.basic_auth_pwd = pwd
    importlib.reload(main)
    yield f"{user}:{pwd}"
    config.basic_auth_user = None
    config.basic_auth_pwd = None
    importlib.reload(main)
