# Copyright 2021 - 2025 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

"""Translation between general and claims specific DAOs."""

from hexkit.protocols.dao import DaoFactoryProtocol
from pydantic import Field
from pydantic_settings import BaseSettings

from ..models.claims import Claim as ClaimDto
from ..ports.dao import ClaimDao, ClaimDaoFactoryPort

__all__ = ["ClaimDaoConfig", "ClaimDaoFactory"]


class ClaimDaoConfig(BaseSettings):
    """User claims DAO config parameters and their defaults."""

    claims_collection: str = Field(
        default="claims", description="Name of the collection for user claims"
    )


class ClaimDaoFactory(ClaimDaoFactoryPort):
    """Translation between ClaimsDaoFactoryPort and DaoFactoryProtocol."""

    def __init__(
        self, *, config: ClaimDaoConfig, dao_factory: DaoFactoryProtocol
    ) -> None:
        """Configure with provider for the DaoFactoryProtocol"""
        self._collection = config.claims_collection
        self._dao_factory = dao_factory

    async def get_claim_dao(self) -> ClaimDao:
        """Construct a DAO for interacting with user claims data in a database."""
        return await self._dao_factory.get_dao(
            name=self._collection,
            dto_model=ClaimDto,
            id_field="id",
            # fields_to_index=["user_id", "visa_type"], #  not yet supported
        )
