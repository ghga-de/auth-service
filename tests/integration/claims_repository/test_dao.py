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

"""Test user specific DAOs."""

import pytest
from ghga_service_commons.utils.utc_dates import utc_datetime
from hexkit.providers.mongodb.testutils import MongoDbFixture

from auth_service.claims_repository.models.claims import Claim, VisaType
from auth_service.claims_repository.translators.dao import (
    ClaimDaoFactory,
)
from auth_service.config import get_config


@pytest.mark.asyncio()
async def test_claim_creation(mongodb: MongoDbFixture):
    """Test creating a new user claim"""
    dao_factory = mongodb.dao_factory
    claim_dao_factory = ClaimDaoFactory(config=get_config(), dao_factory=dao_factory)
    claim_dao = await claim_dao_factory.get_claim_dao()

    claim = Claim(
        user_id="some-internal-user-id",
        visa_type=VisaType.GHGA_ROLE,
        visa_value="data_steward@ghga.de",
        assertion_date=utc_datetime(2022, 9, 1),
        valid_from=utc_datetime(2022, 10, 1),
        valid_until=utc_datetime(2022, 10, 31),
        source="https://ghga.de",  # type: ignore
        creation_date=utc_datetime(2022, 9, 15),
    )
    await claim_dao.insert(claim)
    assert claim.id is not None
    assert claim.sub_source is None
    assert claim.asserted_by is None
    assert claim.conditions is None
    assert claim.revocation_date is None
