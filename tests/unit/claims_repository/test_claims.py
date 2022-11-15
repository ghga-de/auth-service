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

"""Unit tests for the core claims module."""

from datetime import datetime, timezone

from auth_service.config import CONFIG
from auth_service.user_management.claims_repository.core.claims import (
    is_data_steward_claim,
    is_valid_claim,
)
from auth_service.user_management.claims_repository.models.dto import (
    AuthorityLevel,
    Claim,
    VisaType,
)

UTC = timezone.utc


def test_is_valid_claim():
    """Test that claims can be checked for validity."""
    claim = Claim(
        id="claim-id",
        user_id="user-id",
        visa_type=VisaType.RESEARCHER_STATUS,
        visa_value="https://home.org",
        source="https://home.org",
        assertion_date=datetime(2022, 11, 1, tzinfo=UTC),
        valid_from=datetime(2022, 11, 15, tzinfo=UTC),
        valid_until=datetime(2022, 11, 20, tzinfo=UTC),
        creation_date=datetime(2022, 11, 1, tzinfo=UTC),
        creation_by="user-id",
    )
    assert is_valid_claim(claim, now=lambda: datetime(2022, 11, 17, tzinfo=UTC))
    assert not is_valid_claim(claim, now=lambda: datetime(2020, 1, 1, tzinfo=UTC))
    assert not is_valid_claim(claim, now=lambda: datetime(2022, 11, 7, tzinfo=UTC))
    assert not is_valid_claim(claim, now=lambda: datetime(2022, 11, 27, tzinfo=UTC))
    assert not is_valid_claim(claim, now=lambda: datetime(2029, 12, 31, tzinfo=UTC))
    claim = claim.copy(update=dict(revocation_date=datetime(2022, 11, 30, tzinfo=UTC)))
    assert not is_valid_claim(claim, now=lambda: datetime(2020, 1, 1, tzinfo=UTC))
    assert not is_valid_claim(claim, now=lambda: datetime(2022, 11, 17, tzinfo=UTC))
    assert not is_valid_claim(claim, now=lambda: datetime(2029, 12, 31, tzinfo=UTC))


def test_is_data_steward_claim():
    """Test that the data steward role can be derived from a claim."""
    good_claim = Claim(
        id="claim-id",
        user_id="user-id",
        visa_type=VisaType.GHGA_ROLE,
        visa_value="data_steward@some.org",
        source=CONFIG.organization_url,
        assertion_date=datetime(2022, 11, 1, tzinfo=UTC),
        asserted_by=AuthorityLevel.SYSTEM,
        valid_from=datetime(2022, 11, 15, tzinfo=UTC),
        valid_until=datetime(2022, 11, 20, tzinfo=UTC),
        creation_date=datetime(2022, 11, 1, tzinfo=UTC),
        creation_by="user-id",
    )
    assert is_data_steward_claim(good_claim)

    bad_claim = good_claim.copy(update=dict(visa_type=VisaType.AFFILIATION_AND_ROLE))
    assert is_data_steward_claim(good_claim)
    bad_claim = good_claim.copy(update=dict(visa_type=VisaType.AFFILIATION_AND_ROLE))
    assert not is_data_steward_claim(bad_claim)
    bad_claim = good_claim.copy(update=dict(source="https://wrong.org"))
    assert not is_data_steward_claim(bad_claim)
    bad_claim = good_claim.copy(update=dict(asserted_by=None))
    assert not is_data_steward_claim(bad_claim)
    bad_claim = good_claim.copy(update=dict(asserted_by=AuthorityLevel.SELF))
    assert not is_data_steward_claim(bad_claim)
    bad_claim = good_claim.copy(update=dict(visa_value="data_inspector"))
    assert not is_data_steward_claim(bad_claim)
    bad_claim = good_claim.copy(update=dict(visa_value=["data_steward@some.org"]))
    assert not is_data_steward_claim(bad_claim)
