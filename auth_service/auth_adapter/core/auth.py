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
from datetime import datetime
from typing import Any, Optional

from jwcrypto import jwk, jwt

from ...config import CONFIG, Config
from ...deps import Depends, UserDao
from ...user_management.models.dto import StatusChange, User, UserStatus

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
            self.external_jwks = jwk.JWKSet.from_json(external_keys)
        else:
            raise RuntimeError("No external signing keys configured.")
        internal_keys = config.auth_int_keys
        if internal_keys:
            self.internal_jwk = jwk.JWK.from_json(internal_keys)
        else:
            raise RuntimeError("No internal signing keys configured.")
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


def _compare_user(user: User, external_claims: dict[str, Any]) -> Optional[str]:
    """Compare user with external claims and return inactivation context."""
    if user.status == UserStatus.ACTIVATED:
        if user.name != external_claims.get("name"):
            return "name change"
        if user.email != external_claims.get("email"):
            return "email change"
    return None


def _get_inactivated_user(user: User, context: str) -> User:
    """Get an inactivated copy of the User object."""
    return user.copy(
        update=dict(
            status=UserStatus.INACTIVATED.value,
            status_change=StatusChange(
                previous=user.status,
                by=None,
                context=context,
                change_date=datetime.now(),
            ),
        )
    )


async def exchange_token(
    external_token: Optional[str], pass_sub: bool = False, user_dao: UserDao = Depends()
) -> Optional[str]:
    """Exchange the external token against an internal token.

    If the provided external token is valid, a corresponding internal token
    will be returned. Otherwise None will be returned.

    The internal token will contain the name and email taken from the
    external token, and also its issued date and expiry date.
    If the user is already registered, the user id and status will be
    included in the internal token as well.
    If name or email do not match with the external token, the user
    is automatically deactivated in the database and internal token.
    If the user is not yet registered, and pass_sub is set, then the sub claim
    will be included in the internal token as "ls_id", otherwise and empty string
    will be returned instead of the internal token.
    """
    external_claims = decode_and_validate_token(external_token)
    if not external_claims:
        return None  # invalid token (error)
    internal_claims = {
        claim: external_claims[claim] for claim in jwt_config.copied_claims
    }
    sub = external_claims["sub"]
    try:
        user = await user_dao.find_one(mapping={"ls_id": sub})
    except Exception as exc:  # pylint:disable=broad-except
        log.warning("Error retrieving user: %s", exc)
        user = None
    if user is None:
        # user is not yet in the registry
        if not pass_sub:
            return ""  # empty token (no error)
        internal_claims[jwt_config.copy_sub_as] = sub
    else:
        # user already exists in the registry
        context = _compare_user(user, external_claims)
        if context:
            user = _get_inactivated_user(user, context)
            try:
                await user_dao.update(user)
            except Exception as exc:  # pylint:disable=broad-except
                log.warning("Error updating user: %s", exc)
        internal_claims.update(id=user.id, status=user.status)
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
    except Exception as exc:  # pylint:disable=broad-except
        log.error("Error while signing JTW: %s", exc)  # pragma: no cover
    return token
