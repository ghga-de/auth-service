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

"Routes for managing users"

import logging

from fastapi import APIRouter
from fastapi.exceptions import HTTPException

from ...models.dto import User, UserData
from ...ports.dao import UserDao
from ..deps import Depends, get_user_dao

__all__ = ["router"]

log = logging.getLogger(__name__)

router = APIRouter()


@router.post(
    "/users",
    operation_id="post_user",
    tags=["users"],
    summary="Register a user",
    description="Endpoint used to register a new user."
    " May only be performed by the users themselves."
    " Data delivered by the OIDC provider may not be altered.",
    responses={
        201: {"model": User, "description": "User was successfully registered."},
        400: {"description": "User cannot be registered."},
        409: {"description": "User was already registered."},
        422: {"description": "Validation error in submitted user data."},
    },
    status_code=201,
)
async def post_user(
    user_data: UserData, user_dao: UserDao = Depends(get_user_dao)
) -> User:
    """Register a user"""
    ls_id = user_data.ls_id.__root__
    user = await user_dao.find_one(mapping={"ls_id": ls_id})
    if user:
        raise HTTPException(status_code=409, detail="User was already registered.")
    try:
        user = await user_dao.insert(user_data)
    except Exception as error:
        log.error("Could not insert user: %s", error)
        raise HTTPException(
            status_code=400, detail="User cannot be registered."
        ) from error
    return user
