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

"""Methods for processing authorization tokens."""

import json
import logging
from typing import Any, Optional

from jwcrypto import jwk, jwt

from ...config import CONFIG, Config

__all__ = ["exchange_token", "jwt_config"]

log = logging.getLogger(__name__)


class JWTConfig:
    """A container for the JWT related configuration."""

    external_jwks: Optional[jwk.JWKSet] = None  # the external public key set
    internal_jwk: Optional[jwk.JWK] = None  # the internal key pair
    external_algs: Optional[list[str]] = None  # allowed external signing algorithms
    check_claims: dict[str, Any] = {  # claims that shall be verified
        "iat": None,
        "exp": None,
        "jti": None,
        "sub": None,
        "name": None,
        "email": None,
        "token_class": "access_token",
    }
    # the claims that are copied from the external to the internal token
    copied_claims = ("name", "email", "iat", "exp")
    # the key under which the subject is copied from the external token
    copy_sub_as = "ls_id"

    def __init__(self, config: Config = CONFIG) -> None:
        """Load the JWT related configuration parameters."""

        external_keys = config.auth_ext_keys
        if external_keys:
            try:
                self.external_jwks = jwk.JWKSet.from_json(external_keys)
            except Exception as exc:  # pylint:disable=broad-except
                # do not throw an error so that the auth adapter can still run
                # even though it will not be able to validate external tokens
                log.error("Cannot parse external signing keys: %s", exc)
        else:
            log.error("No external signing keys configured.")
        internal_keys = config.auth_int_keys
        if internal_keys:
            try:
                self.internal_jwk = jwk.JWK.from_json(internal_keys)
            except Exception as exc:  # pylint:disable=broad-except
                # do not throw an error so that the auth adapter can still run
                # even though it will not be able to sign internal tokens
                log.error("Cannot parse internal signing key pair: %s", exc)
        else:
            log.error("No internal signing keys configured.")
        external_algs = config.auth_ext_algs
        if external_algs:
            self.external_algs = external_algs
        else:
            log.warning("Allowed external signing algorithms not configured.")
        authority_url = config.oidc_authority_url
        if authority_url:
            self.check_claims["iss"] = authority_url
        else:
            log.warning("No OIDC authority URL configured.")
        client_id = config.oidc_client_id
        if client_id:
            self.check_claims["client_id"] = client_id
        else:
            log.warning("No OIDC client ID configured.")


jwt_config = JWTConfig()


def exchange_token(
    external_token: Optional[str], with_sub: bool = False
) -> Optional[str]:
    """Exchange the external token against an internal token.

    If the provided external token is valid, a corresponding internal token
    will be returned. Otherwise None will be returned.

    If with_sub is set, then the subject will be passed as well.
    """
    external_claims = decode_and_validate_token(external_token)
    if not external_claims:
        return None
    internal_claims = {
        claim: external_claims[claim] for claim in jwt_config.copied_claims
    }
    if with_sub:
        internal_claims[jwt_config.copy_sub_as] = external_claims["sub"]
    internal_token = sign_and_encode_token(internal_claims)
    return internal_token


def decode_and_validate_token(
    access_token: Optional[str], key=None
) -> Optional[dict[str, Any]]:
    """Decode and validate the given JSON Web Token."""
    if not access_token:
        return None
    if not key:
        key = jwt_config.external_jwks
        if not key:
            log.debug("No external signing key, cannot validate token.")
            return None
    try:
        token = jwt.JWT(
            jwt=access_token,
            key=key,
            algs=jwt_config.external_algs,
            check_claims=jwt_config.check_claims,
            expected_type="JWS",
        )
        claims = json.loads(token.claims)
        # in addition to JWT.validate() which checks whether claims exist,
        # we also make sure that the copied claims are not null or empty strings
        if not claims["sub"]:
            raise ValueError("The subject claim is missing.")
        for claim in jwt_config.copied_claims:
            if not claims[claim]:
                raise ValueError(f"Missing value for {claim} claim.")
        return claims
    except Exception as exc:  # pylint:disable=broad-except
        log.debug("Cannot validate external token: %s", exc)
    return None


def sign_and_encode_token(claims: dict[str, Any], key=None) -> Optional[str]:
    """Encode and sign the given payload as JSON Web Token.

    Returns None in case the payload could not be properly signed.
    """
    if not claims:
        return None
    if not key:
        key = jwt_config.internal_jwk
        if not key:
            log.debug("No internal signing key, cannot sign token.")
            return None
    try:
        header = {"alg": "ES256" if key["kty"] == "EC" else "RS256", "typ": "JWT"}
        token = jwt.JWT(header=header, claims=claims)
        token.make_signed_token(key)
        return token.serialize(compact=True)
    except Exception as exc:  # pylint:disable=broad-except:
        log.error("Error while signing JTW: %s", exc)  # pragma: no cover
    return token
