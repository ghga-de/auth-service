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

from jwcrypto import jwk
from pytest import fixture

from auth_service.auth_adapter.core.jwks import external_jwks


@fixture(name="external_key")
def fixture_external_key():
    """Generate a key pair and add it to the external key set."""
    key = jwk.JWK.generate(kty="RSA", size=2048)
    external_jwks.add(key)
    yield key
    external_jwks["keys"].remove(key)
