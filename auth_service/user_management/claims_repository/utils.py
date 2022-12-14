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
#

"""
Core utilities for the Claims Repository.
"""

from hexkit.protocols.dao import ResourceNotFoundError

from auth_service.user_management.user_registry.deps import UserDao


async def user_exists(user_id: str, user_dao: UserDao) -> bool:
    """Check whether the user with the given id exists."""
    try:
        await user_dao.get_by_id(user_id)
    except ResourceNotFoundError:
        return False
    else:
        return True
