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

import logging
from datetime import datetime

from jwcrypto import jwk

from auth_service.auth_adapter.core.auth import decode_and_validate_token, jwt_config
from auth_service.config import CONFIG

from ...fixtures.utils import create_access_token


def test_decodes_and_validates_a_valid_access_token(caplog):
    """Test that a valid access token is decoded and validated."""
    caplog.set_level(logging.DEBUG)
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
    assert claims["iat"] <= int(datetime.now().timestamp()) < claims["exp"]
    assert not caplog.records


def test_validates_access_token_with_rsa_signature(caplog):
    """Test that an access tokens with RSA signature can be validated."""
    key = jwk.JWK.generate(kty="RSA", size=1024)
    access_token = create_access_token(key=key)
    claims = decode_and_validate_token(access_token, key=key)
    assert isinstance(claims, dict)
    assert claims["name"] == "John Doe"
    assert not caplog.records


def test_validates_access_token_with_ec_signature(caplog):
    """Test that an access tokens with EC signature can be validated."""
    key = jwk.JWK.generate(kty="EC", crv="P-256")
    access_token = create_access_token(key=key)
    claims = decode_and_validate_token(access_token, key=key)
    assert isinstance(claims, dict)
    assert claims["name"] == "John Doe"
    assert not caplog.records


def test_does_not_validate_an_access_token_with_bad_signature(caplog):
    """Test that an access token with a corrupt signature is rejected."""
    caplog.set_level(logging.DEBUG)
    access_token = create_access_token()
    access_token = ".".join(access_token.split(".")[:-1] + ["somebadsignature"])
    assert decode_and_validate_token(access_token) is None
    assert len(caplog.records) == 1
    assert caplog.records[0].message == "Cannot validate external token: Missing Key"


def test_does_not_validate_an_access_token_when_external_key_is_missing(caplog):
    """Test that an access token is not validated if no external key is provided."""
    caplog.set_level(logging.DEBUG)
    access_token = create_access_token()
    external_jwks, jwt_config.external_jwks = jwt_config.external_jwks, None
    try:
        assert decode_and_validate_token(access_token) is None
    finally:
        jwt_config.external_jwks = external_jwks
    assert len(caplog.records) == 1
    assert (
        caplog.records[0].message == "No external signing key, cannot validate token."
    )


def test_does_not_validate_an_access_token_when_alg_is_not_allowed(caplog):
    """Test that an access token must be signed with an allowed alogorithm."""
    caplog.set_level(logging.DEBUG)
    access_token = create_access_token()
    external_algs = jwt_config.external_algs
    assert isinstance(external_algs, list)
    jwt_config.external_algs = external_algs[:]
    try:
        jwt_config.external_algs.remove("ES256")
        assert decode_and_validate_token(access_token) is None
    finally:
        jwt_config.external_algs = external_algs
    assert len(caplog.records) == 1
    assert caplog.records[0].message == "Cannot validate external token: Missing Key"


def test_does_not_validate_an_access_token_with_invalid_client_id(caplog):
    """Test that an access token with an unknown client id is rejected."""
    caplog.set_level(logging.DEBUG)
    access_token = create_access_token(client_id="some-bad-client")
    assert decode_and_validate_token(access_token) is None
    assert len(caplog.records) == 1
    assert (
        caplog.records[0].message == "Cannot validate external token:"
        " Invalid 'client_id' value. Expected 'ghga-data-portal' got 'some-bad-client'"
    )


def test_does_not_validate_an_access_token_with_invalid_issuer(caplog):
    """Test that an access token with an unknown issuer is rejected."""
    caplog.set_level(logging.DEBUG)
    access_token = create_access_token(iss="https://proxy.aai.badscience-ri.eu")
    assert decode_and_validate_token(access_token) is None
    assert len(caplog.records) == 1
    assert (
        caplog.records[0].message == "Cannot validate external token:"
        " Invalid 'iss' value. Expected 'https://proxy.aai.lifescience-ri.eu'"
        " got 'https://proxy.aai.badscience-ri.eu'"
    )


def test_does_not_validate_an_access_token_with_missing_subject(caplog):
    """Test that an access token with a missing subject is rejected."""
    caplog.set_level(logging.DEBUG)
    access_token = create_access_token(sub=None)
    assert decode_and_validate_token(access_token) is None
    assert len(caplog.records) == 1
    assert (
        caplog.records[0].message == "Cannot validate external token:"
        " The subject claim is missing."
    )


def test_does_not_validate_an_access_token_with_missing_name(caplog):
    """Test that an access token with a missing name is rejected."""
    caplog.set_level(logging.DEBUG)
    access_token = create_access_token(name=None)
    assert decode_and_validate_token(access_token) is None
    assert len(caplog.records) == 1
    assert (
        caplog.records[0].message == "Cannot validate external token:"
        " Missing value for name claim."
    )


def test_does_not_validate_an_access_token_with_missing_email(caplog):
    """Test that an access token with a missing email is rejected."""
    caplog.set_level(logging.DEBUG)
    access_token = create_access_token(email=None)
    assert decode_and_validate_token(access_token) is None
    assert len(caplog.records) == 1
    assert (
        caplog.records[0].message == "Cannot validate external token:"
        " Missing value for email claim."
    )


def test_does_not_validate_an_expired_access_token(caplog):
    """Test that access tokens that have expired are rejected."""
    caplog.set_level(logging.DEBUG)
    access_token = create_access_token(expired=True)
    assert decode_and_validate_token(access_token) is None
    assert len(caplog.records) == 1
    assert caplog.records[0].message.startswith(
        "Cannot validate external token: Expired at "
    )


def test_does_not_validate_token_with_invalid_payload(caplog):
    """Test that access tokens with invalid payload are rejected."""
    caplog.set_level(logging.DEBUG)
    key = jwk.JWK(kty="oct", k="r0TSf_aAU9eS7I5JPPJ20pmkPmR__9LsfnZaKfXZYp8")
    external_algs, jwt_config.external_algs = jwt_config.external_algs, ["HS256"]
    try:
        token_with_valid_payload = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiAiSm9obiBEb2UifQ."
            "RQYHxFwGjMdVh-umuuA1Yd4Ssx6TAYkg1INYK6_lKVw"
        )
        assert decode_and_validate_token(token_with_valid_payload, key=key) is None
        token_with_text_as_payload = (
            "eyJhbGciOiJIUzI1NiJ9."
            "VGhpcyBpcyBub3QgSlNPTiE."
            "bKt6NQoZGLOLqqqB-XT99ENnsmv-hxLId08FxR4LUOw"
        )
        assert decode_and_validate_token(token_with_text_as_payload, key=key) is None
        token_with_bad_encoding = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiAiRnLpZOlyaWMgQ2hvcGluIn0."
            "8OTfVB6CN2pXgPHZBPdbkqWGd2XhtbVDhlcYdYNh6d4"
        )
        assert decode_and_validate_token(token_with_bad_encoding, key=key) is None
    finally:
        jwt_config.external_algs = external_algs
    messages = [rec.message for rec in caplog.records]
    assert len(messages) == 3
    assert all(msg.startswith("Cannot validate external token:") for msg in messages)
    assert "iat is missing" in messages[0]
    assert "not a json dict" in messages[1]
    assert "can't decode" in messages[2]
