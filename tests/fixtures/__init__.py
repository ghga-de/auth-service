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
from typing import Generator

from pytest import fixture

from auth_service.auth_adapter.core import auth
from auth_service.config import CONFIG


@fixture(name="signing_keys")
def fixture_signing_keys(caplog) -> auth.SigningKeys:
    """Get signing key instance with random keys for testing."""
    caplog.set_level(logging.WARNING)
    caplog.clear()
    auth.signing_keys.load(CONFIG)
    assert [
        record.message for record in caplog.records if record.levelname == "WARNING"
    ] == [
        "No external keys configured, generating random ones.",
        "No internal keys configured, generating random ones.",
    ]
    caplog.clear()
    return auth.signing_keys


@fixture(name="signing_keys_full")
def fixture_signing_keys_full(signing_keys) -> Generator[auth.SigningKeys, None, None]:
    """Get signing key instance with full external key for testing."""
    external_jwks = signing_keys.external_jwks
    full_external_jwk = signing_keys.generate()
    signing_keys.external_jwks = external_jwks.__class__()
    signing_keys.external_jwks.add(full_external_jwk)
    yield signing_keys
    signing_keys.external_jwks = external_jwks
