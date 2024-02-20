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

"""Port for managing and using TOTP tokens."""

from abc import ABC, abstractmethod
from typing import Generic, Optional, TypeVar

from ghga_service_commons.utils.utc_dates import UTCDatetime
from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class TOTPHandlerPort(ABC, Generic[T]):
    """Port for a handler that can manage and use TOTP tokens."""

    @classmethod
    @abstractmethod
    def random_encryption_key(cls) -> str:
        """Generate random Base64 key of given size for encrypting secrets."""
        ...

    @abstractmethod
    def get_secret(self, token: T) -> str:
        """Get the decrypted Base32 encoded secret from a TOTP token."""
        ...

    @abstractmethod
    def generate_token(self) -> T:
        """Generate a TOTP token."""
        ...

    @abstractmethod
    def generate_code(
        self,
        token: T,
        for_time: Optional[UTCDatetime] = None,
        counter_offset: int = 0,
    ) -> str:
        """Generate a TOTP code for testing purposes."""
        ...

    @abstractmethod
    def verify_code(
        self,
        token: T,
        code: str,
        for_time: Optional[UTCDatetime] = None,
    ) -> Optional[bool]:
        """Verify a TOTP token with replay attack prevention and rate limiting.

        A return value of True means that the code is valid.
        If the return value is None, the usage parameters of the token have
        been changed and the token should be saved back to the database.
        """
        ...
