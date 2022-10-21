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

"""Utils for fixture handling"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from jwcrypto import jwk, jwt

from auth_service.auth_adapter.core.auth import jwt_config

BASE_DIR = Path(__file__).parent.resolve()


def create_access_token(
    key: Optional[jwk.JWK] = None, expired: bool = False, **kwargs
) -> str:
    """Create an external access token that can be used for testing."""
    if not key:
        keyset = jwt_config.external_jwks
        assert isinstance(keyset, jwk.JWKSet)
        key = keyset.get_key("test")
    assert isinstance(key, jwk.JWK)
    kty = key["kty"]
    assert kty in ("EC", "RSA")
    header = {"alg": "ES256" if kty == "EC" else "RS256", "typ": "JWT"}
    claims = jwt_config.check_claims.copy()
    claims.update(
        name="John Doe",
        email="john@home.org",
        jti="1234567890",
        sub="john@aai.org",
        foo="bar",
    )
    iat = int(datetime.now().timestamp())
    exp = iat + 60
    if expired:
        iat -= 120
        exp -= 120
    claims.update(iat=iat, exp=exp)
    claims.update(kwargs)
    token = jwt.JWT(header=header, claims=claims)
    token.make_signed_token(key)
    access_token = token.serialize()
    assert isinstance(access_token, str)
    assert len(access_token) > 50
    assert access_token.count(".") == 2
    return access_token


def get_claims_from_token(token: str, key: Optional[jwk.JWK] = None) -> dict[str, Any]:
    """Decode given the JWT tokenand get its claims."""
    if not key:
        key = jwt_config.internal_jwk
    assert isinstance(key, jwk.JWK)
    assert isinstance(token, str)
    assert len(token) > 50
    assert token.count(".") == 2
    claims = json.loads(jwt.JWT(jwt=token, key=key).claims)
    assert isinstance(claims, dict)
    return claims
