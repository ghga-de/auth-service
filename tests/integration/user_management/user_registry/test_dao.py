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

"""Test user specific DAOs."""

from ghga_service_commons.utils.utc_dates import utc_datetime
from hexkit.providers.mongodb.testutils import mongodb_fixture  # noqa: F401
from pytest import mark

from auth_service.user_management.user_registry.core.registry import UserRegistry
from auth_service.user_management.user_registry.deps import (
    get_config,
    get_user_dao_factory,
)
from auth_service.user_management.user_registry.models.users import (
    AcademicTitle,
    StatusChange,
    User,
    UserData,
    UserStatus,
)


@mark.asyncio()
async def test_user_creation(
    mongodb_fixture,  # noqa: F811
):
    """Test creating a new user"""
    user_dao_factory = get_user_dao_factory(
        config=get_config(), dao_factory=mongodb_fixture.dao_factory
    )
    user_dao = await user_dao_factory.get_user_dao()

    user_data = UserData(
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

    for op in ("insert", "get"):
        user = await (
            user_dao.insert(user_data)
            if op == "insert"
            else user_dao.find_one(mapping={"ext_id": user_data.ext_id})
        )

        assert user and isinstance(user, User)
        assert user.ext_id == user_data.ext_id
        assert user.status == user_data.status
        assert user.name == user_data.name
        assert user.title == user_data.title
        assert user.email == user_data.email
        assert user.registration_date == user_data.registration_date
        assert UserRegistry.is_internal_user_id(user.id)
        assert user.status_change == user_data.status_change
