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

"""DTOs for the user management service

Note: we currently use the DTOs also as the core entities.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, Field

__all__ = ["User", "UserData"]


class ID(BaseModel):
    """ID component"""

    __root__: str = Field(  # actually UUID4
        ..., title="ID", description="Internally used ID"
    )


class LSID(BaseModel):
    """LS ID component"""

    __root__: EmailStr = Field(
        ...,
        title="LS ID",
        description="Life Science ID",
        example="user@lifescience-ri.eu",
    )


class UserStatusEnum(str, Enum):
    """User status enum"""

    REGISTERED = "registered"
    ACTIVATED = "activated"
    INACTIVATED = "inactivated"
    DELETED = "deleted"


class UserStatus(BaseModel):
    """User status component"""

    __root__: UserStatusEnum = Field(
        ..., title="Status", description="Registration status of the user"
    )


class FullName(BaseModel):
    """Full name component"""

    __root__: str = Field(
        ...,
        title="Name",
        description="Full name of the user",
        example="Rosalind Franklin",
    )


class AcademicTitleEnum(str, Enum):
    """Academic title"""

    DR = "Dr."
    PROF = "Prof."


class AcademicTitle(BaseModel):
    """Academic title component"""

    __root__: AcademicTitleEnum = Field(
        ...,
        title="Academic title",
        description="Academic title of the user (only Dr. or Prof.)",
    )


class EMail(BaseModel):
    """E-Mail component"""

    __root__: EmailStr = Field(
        ...,
        title="E-Mail",
        description="Preferred e-mail address of the user",
        example="user@home.org",
    )


class UserData(BaseModel):
    """User data"""

    ls_id: LSID

    status: UserStatus

    name: FullName
    title: Optional[AcademicTitle]
    email: EmailStr

    research_topics: Optional[str] = Field(default=None, title="Research topic(s)")

    registration_reason: Optional[str] = Field(
        default=None, title="Reason for registration"
    )
    registration_date: datetime = Field(default=..., title="Resitration date")

    class Config:  # pylint: disable=missing-class-docstring
        frozen = True
        use_enum_values = True


class User(UserData):
    """User"""

    id: ID
