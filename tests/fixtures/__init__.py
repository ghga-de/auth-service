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

"""Fixtures that are used in both integration and unit tests"""

import logging

from pytest import fixture

from auth_service.auth_adapter.core.auth import SigningKeys, signing_keys
from auth_service.config import CONFIG


@fixture(name="signing_keys")
def fixture_signing_keys(caplog) -> SigningKeys:
    """Get signing key instance with random keys for testing."""
    caplog.set_level(logging.WARNING)
    caplog.clear()
    signing_keys.load(CONFIG)
    assert [
        record.message for record in caplog.records if record.levelname == "WARNING"
    ] == [
        "No external keys configured, generating random ones.",
        "No internal keys configured, generating random ones.",
    ]
    caplog.clear()
    assert signing_keys.full_external_jwk
    return signing_keys
