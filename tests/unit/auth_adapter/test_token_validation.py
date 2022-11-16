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

"""Unit tests for the core token validation feature"""

from jwcrypto import jwk
from pytest import raises

from auth_service.auth_adapter.core.auth import (
    TokenValidationError,
    decode_and_validate_token,
    jwt_config,
)
from auth_service.config import CONFIG
from auth_service.user_management.utils import now_as_utc

from ...fixtures.utils import create_access_token


def test_decodes_and_validates_a_valid_access_token():
    """Test that a valid access token is decoded and validated."""
    access_token = create_access_token()
    claims = decode_and_validate_token(access_token)
    assert isinstance(claims, dict)
    assert set(claims) == {
        "client_id",
        "email",
        "exp",
        "foo",
        "iat",
        "iss",
        "jti",
        "name",
        "sub",
        "token_class",
    }
    assert claims["client_id"] == CONFIG.oidc_client_id
    assert claims["iss"] == CONFIG.oidc_authority_url
    assert claims["name"] == "John Doe"
    assert claims["email"] == "john@home.org"
    assert claims["jti"] == "1234567890"
    assert claims["sub"] == "john@aai.org"
    assert claims["foo"] == "bar"
    assert claims["token_class"] == "access_token"
    assert isinstance(claims["iat"], int)
    assert isinstance(claims["exp"], int)
    assert claims["iat"] <= int(now_as_utc().timestamp()) < claims["exp"]


def test_validates_access_token_with_rsa_signature():
    """Test that an access tokens with RSA signature can be validated."""
    key = jwk.JWK.generate(kty="RSA", size=1024)
    access_token = create_access_token(key=key)
    claims = decode_and_validate_token(access_token, key=key)
    assert isinstance(claims, dict)
    assert claims["name"] == "John Doe"


def test_validates_access_token_with_ec_signature():
    """Test that an access tokens with EC signature can be validated."""
    key = jwk.JWK.generate(kty="EC", crv="P-256")
    access_token = create_access_token(key=key)
    claims = decode_and_validate_token(access_token, key=key)
    assert isinstance(claims, dict)
    assert claims["name"] == "John Doe"


def test_does_not_validate_an_empty_token():
    """Test that an empty access token rejected."""
    with raises(TokenValidationError, match="Empty token"):
        decode_and_validate_token(None)  # type: ignore
    with raises(TokenValidationError, match="Empty token"):
        decode_and_validate_token("")


def test_does_not_validate_an_access_token_with_wrong_format():
    """Test that an access token with a completely wrong format is rejected."""
    access_token = "random.garbage"
    with raises(TokenValidationError, match="Token format unrecognized"):
        decode_and_validate_token(access_token)


def test_does_not_validate_an_access_token_with_bad_signature():
    """Test that an access token with a corrupt signature is rejected."""
    access_token = create_access_token()
    access_token = ".".join(access_token.split(".")[:-1] + ["somebadsignature"])
    with raises(TokenValidationError, match="Not a valid token: Missing Key"):
        decode_and_validate_token(access_token)


def test_does_not_validate_an_access_token_when_external_key_is_missing():
    """Test that an access token is not validated if no external key is provided."""
    access_token = create_access_token()
    external_jwks, jwt_config.external_jwks = jwt_config.external_jwks, None
    try:
        with raises(TokenValidationError) as exc_info:
            decode_and_validate_token(access_token)
    finally:
        jwt_config.external_jwks = external_jwks
    assert str(exc_info.value) == "No external signing key(s), cannot validate token."


def test_does_not_validate_an_access_token_when_alg_is_not_allowed():
    """Test that an access token must be signed with an allowed algorithm."""
    access_token = create_access_token()
    external_algs = jwt_config.external_algs
    assert isinstance(external_algs, list)
    jwt_config.external_algs = external_algs[:]
    try:
        jwt_config.external_algs.remove("ES256")
        with raises(TokenValidationError, match="Not a valid token: Missing Key"):
            decode_and_validate_token(access_token)
    finally:
        jwt_config.external_algs = external_algs


def test_does_not_validate_an_access_token_with_invalid_client_id():
    """Test that an access token with an unknown client id is rejected."""
    access_token = create_access_token(client_id="some-bad-client")
    with raises(TokenValidationError) as exc_info:
        decode_and_validate_token(access_token)
    assert str(exc_info.value) == (
        "Not a valid token: Invalid 'client_id' value."
        " Expected 'ghga-data-portal' got 'some-bad-client'"
    )


def test_does_not_validate_an_access_token_with_invalid_issuer():
    """Test that an access token with an unknown issuer is rejected."""
    access_token = create_access_token(iss="https://proxy.aai.badscience-ri.eu")
    with raises(TokenValidationError) as exc_info:
        decode_and_validate_token(access_token)
    assert str(exc_info.value) == (
        "Not a valid token: Invalid 'iss' value."
        " Expected 'https://proxy.aai.lifescience-ri.eu'"
        " got 'https://proxy.aai.badscience-ri.eu'"
    )


def test_does_not_validate_an_access_token_with_missing_subject():
    """Test that an access token with a missing subject is rejected."""
    access_token = create_access_token(sub=None)
    with raises(TokenValidationError) as exc_info:
        decode_and_validate_token(access_token)
    assert str(exc_info.value) == "The subject claim is missing."


def test_does_not_validate_an_access_token_with_missing_name():
    """Test that an access token with a missing name is rejected."""
    access_token = create_access_token(name=None)
    with raises(TokenValidationError) as exc_info:
        decode_and_validate_token(access_token)
    assert str(exc_info.value) == "Missing value for name claim."


def test_does_not_validate_an_access_token_with_missing_email():
    """Test that an access token with a missing email is rejected."""
    access_token = create_access_token(email=None)
    with raises(TokenValidationError) as exc_info:
        decode_and_validate_token(access_token)
    assert str(exc_info.value) == "Missing value for email claim."


def test_does_not_validate_an_expired_access_token():
    """Test that access tokens that have expired are rejected."""
    access_token = create_access_token(expired=True)
    with raises(TokenValidationError, match="Not a valid token: Expired"):
        decode_and_validate_token(access_token)


def test_does_not_validate_token_with_invalid_payload():
    """Test that access tokens with invalid payload are rejected."""
    key = jwk.JWK(kty="oct", k="r0TSf_aAU9eS7I5JPPJ20pmkPmR__9LsfnZaKfXZYp8")
    external_algs, jwt_config.external_algs = jwt_config.external_algs, ["HS256"]
    try:
        token_with_valid_payload = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiAiSm9obiBEb2UifQ."
            "RQYHxFwGjMdVh-umuuA1Yd4Ssx6TAYkg1INYK6_lKVw"
        )
        with raises(
            TokenValidationError, match="Not a valid token: Claim iat is missing"
        ):
            decode_and_validate_token(token_with_valid_payload, key=key)
        token_with_text_as_payload = (
            "eyJhbGciOiJIUzI1NiJ9."
            "VGhpcyBpcyBub3QgSlNPTiE."
            "bKt6NQoZGLOLqqqB-XT99ENnsmv-hxLId08FxR4LUOw"
        )
        with raises(
            TokenValidationError, match="Not a valid token: .* not a json dict"
        ):
            decode_and_validate_token(token_with_text_as_payload, key=key)
        token_with_bad_encoding = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiAiRnLpZOlyaWMgQ2hvcGluIn0."
            "8OTfVB6CN2pXgPHZBPdbkqWGd2XhtbVDhlcYdYNh6d4"
        )
        with raises(TokenValidationError, match="'utf-8' codec can't decode"):
            decode_and_validate_token(token_with_bad_encoding, key=key)
    finally:
        jwt_config.external_algs = external_algs
