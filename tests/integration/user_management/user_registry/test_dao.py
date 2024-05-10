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

"""Test user specific DAOs."""

import pytest
from ghga_service_commons.utils.utc_dates import utc_datetime
from hexkit.providers.mongodb.testutils import MongoDbFixture

from auth_service.user_management.user_registry.core.registry import UserRegistry
from auth_service.user_management.user_registry.models.users import (
    AcademicTitle,
    StatusChange,
    User,
    UserStatus,
)


@pytest.mark.asyncio()
async def test_user_creation(mongodb: MongoDbFixture):
    """Test creating a new user"""
    user_dao = await mongodb.dao_factory.get_dao(
        name="users", dto_model=User, id_field="id"
    )

    user = User(
        ext_id="max@ls.org",
        status=UserStatus.ACTIVE,
        name="Max Headroom",
        title=AcademicTitle.DR,
        email="max@example.org",
        registration_date=utc_datetime(2022, 9, 1, 12, 0),
        status_change=StatusChange(previous=None, by=None, context="test"),
        active_submissions=["sub-1"],
        active_access_requests=["req-1", "req-2"],
    )

    for insert in True, False:
        if insert:
            await user_dao.insert(user)
        else:
            user = await user_dao.find_one(mapping={"ext_id": user.ext_id})

        assert user and isinstance(user, User)
        assert user.ext_id == user.ext_id
        assert user.status == user.status
        assert user.name == user.name
        assert user.title == user.title
        assert user.email == user.email
        assert user.registration_date == user.registration_date
        assert UserRegistry.is_internal_user_id(user.id)
        assert user.status_change == user.status_change
