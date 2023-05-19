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

"""Fixtures for the user management integration tests"""

import asyncio
from typing import Generator

from fastapi.testclient import TestClient
from ghga_service_commons.utils.utc_dates import now_as_utc
from hexkit.protocols.dao import ResourceNotFoundError
from pydantic import EmailStr
from pytest import fixture
from testcontainers.mongodb import MongoDbContainer

from auth_service.config import Config
from auth_service.deps import get_config, get_mongodb_config, get_mongodb_dao_factory
from auth_service.user_management.api.main import app
from auth_service.user_management.user_registry.models.dto import User, UserStatus


@fixture(name="client")
def fixture_client() -> TestClient:
    """Get test client for the user manager"""
    config = Config(
        include_apis=["claims"],
    )  # pyright: ignore
    app.dependency_overrides[get_config] = lambda: config
    return TestClient(app)


data_steward = User(
    id="the-id-of-rod-steward",
    ext_id=EmailStr("rod@ls.org"),
    name="Rod Steward",
    email=EmailStr("rod@example.org"),
    status=UserStatus.ACTIVE,
    registration_date=now_as_utc(),
)

add_as_data_stewards = [data_steward.ext_id]


async def seed_database(config: Config) -> None:
    """Seed the database with a dummy user that will become a data steward."""
    user_dao = await get_mongodb_dao_factory(config=get_mongodb_config(config)).get_dao(
        name=config.users_collection,
        dto_model=User,
        id_field="id",
    )
    try:
        await user_dao.get_by_id(data_steward.id)
    except ResourceNotFoundError:
        await user_dao.insert(data_steward)


@fixture(name="client_with_db")
def fixture_client_with_db() -> Generator[TestClient, None, None]:
    """Get test client for the user manager with a test database."""

    with MongoDbContainer() as mongodb:
        connection_url = mongodb.get_connection_url()
        config = Config(
            db_url=connection_url,
            db_name="test-claims-repository",
            include_apis=["claims"],
            add_as_data_stewards=add_as_data_stewards,
        )  # pyright: ignore
        asyncio.run(seed_database(config))

        app.dependency_overrides[get_config] = lambda: config
        with TestClient(app) as client:
            yield client
        app.dependency_overrides.clear()