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

"""IVA model classes used as DTOs and core entities.

An IVA is an "indendent verification address" used to verify a user's identity.
"""

from enum import Enum
from typing import Optional

from ghga_service_commons.utils.utc_dates import UTCDatetime
from pydantic import Field

from . import BaseDto

__all__ = ["IVAType", "IVAState", "IvaExternal", "IvaData", "Iva"]


class IVAType(str, Enum):
    """The type of IVA"""

    PHONE = "Phone"
    FAX = "Fax"
    POSTAL_ADDRESS = "PostalAddress"
    IN_PERSON = "InPerson"


class IVAState(str, Enum):
    """The state of an IVA"""

    UNVERIFIED = "Unverified"
    CODE_REQUESTED = "CodeRequested"
    CODE_CREATED = "CodeCreated"
    CODE_TRANSMITTED = "CodeTransmitted"
    CODE_VERIFIED = "CodeVerified"


class IvaBasicData(BaseDto):
    """Basic IVA data"""

    user_id: str = Field(default=..., description="Internal user ID")
    type: IVAType = Field(default=..., description="The type of the IVA")
    value: str = Field(default=..., description="The actual address")
    state: IVAState = Field(
        default=IVAState.UNVERIFIED, description="The state of the IVA"
    )


class IvaInternalData(BaseDto):
    """Internal data of an IVA (not exposed via the API)"""

    verification_code_hash: Optional[str] = Field(
        default=None, description="Hash of the verification code for the IVA"
    )
    verification_attempts: int = Field(
        default=0,
        description="Number of failed verification attempts for the verification code",
    )


class IvaAutomaticDAta(BaseDto):
    """Data that is automatically added to an IVA"""

    created: UTCDatetime = Field(
        default=..., description="The date and time when the IVA was created"
    )
    changed: UTCDatetime = Field(
        default=..., description="The date and time when the IVA was last changed"
    )


class IvaExternal(IvaBasicData, IvaAutomaticDAta):
    """IVA data model including all external data and the ID"""

    id: str = Field(default=..., description="Internal IVA ID")  # actually UUID


class IvaData(IvaBasicData, IvaInternalData, IvaAutomaticDAta):
    """IVA data model including all internal data without ID"""


class Iva(IvaData):
    """IVA data model including internal data and the ID"""

    id: str = Field(default=..., description="Internal IVA ID")  # actually UUID
