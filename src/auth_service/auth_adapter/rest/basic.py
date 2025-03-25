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

"""Basic HTTP authentication"""

import secrets
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from ...config import Config

__all__ = ["get_basic_auth_dependency"]


def get_allowed_credentials(config: Config) -> list[HTTPBasicCredentials]:
    """Get list of allowed credentials from the config.

    User names and passwords must be separated with colons.
    Multiple credentials must be separated by whitespace.
    """
    credentials = config.basic_auth_credentials or ""
    allowed_credentials: list[HTTPBasicCredentials] = []
    for user_and_password in credentials.split():
        try:
            username, password = user_and_password.split(":", 1)
        except ValueError as error:
            raise ValueError(
                "Basic auth credentials must be passed as username:password"
            ) from error
        allowed_credentials.append(
            HTTPBasicCredentials(username=username, password=password)
        )
    return allowed_credentials


def get_basic_auth_dependency(config: Config):
    """Get dependency for Basic authentication if this is configured."""
    allowed_credentials = get_allowed_credentials(config)
    if not allowed_credentials:
        return None
    realm = config.basic_auth_realm
    if not realm:
        return None

    http_basic = HTTPBasic(realm=realm)

    async def check_basic_auth(
        passed_credentials: Annotated[HTTPBasicCredentials, Depends(http_basic)],
    ):
        """Check basic access authentication if username and password are set."""
        for credentials in allowed_credentials:
            # check user and password while avoiding timing attacks
            user_ok = secrets.compare_digest(
                passed_credentials.username, credentials.username
            )
            pwd_ok = secrets.compare_digest(
                passed_credentials.password, credentials.password
            )
            if user_ok and pwd_ok:
                break
        else:
            www_auth = f'Basic realm="{realm}"'
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": www_auth},
            )

    return Depends(check_basic_auth)


def add_basic_auth_exception_handler(app: FastAPI, config: Config):
    """Add an exception handler if needed for Basic authentication."""
    allowed_credentials = get_allowed_credentials(config)
    if not allowed_credentials:
        return None
    realm = config.basic_auth_realm
    if not realm:
        return None

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request, exc):
        """Special exception handler for Basic authentication."""
        status_code, detail = exc.status_code, exc.detail
        response_headers = exc.headers
        # Create a plaintext response for Basic auth exceptions:
        if response_headers and (
            response_headers.get("WWW-Authenticate") or ""
        ).startswith("Basic "):
            return PlainTextResponse(
                f"{realm}: {detail}",
                status_code=status_code,
                headers=response_headers,
            )
        # Change unauthorized status code if the exception did not
        # happen due to a missing Basic Auth, so that the browser
        # does not ask for the Basic auth credentials again.
        # Unfortunately we can do this only for auth adapter responses,
        # but it catches most of the cases where these errors are produced.
        if status_code == status.HTTP_401_UNAUTHORIZED and (
            request.headers.get("Authorization") or ""
        ).startswith("Basic "):
            status_code = status.HTTP_403_FORBIDDEN
        # Create the default JSON response for all other exceptions:
        return JSONResponse(
            {"detail": detail}, status_code=status_code, headers=response_headers
        )
