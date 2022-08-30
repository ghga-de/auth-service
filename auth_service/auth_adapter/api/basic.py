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

"""
Basic HTTP authentication
"""

import secrets

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from .deps import get_config

__all__ = ["basic_auth_injector"]


def basic_auth_injector(app: FastAPI):
    """Inject Basic authentication if user and password are set."""
    config = get_config()
    user, pwd = config.basic_auth_user, config.basic_auth_pwd
    if not (user and pwd):
        return None

    security = HTTPBasic(realm="GHGA Data Portal")

    @app.exception_handler(HTTPException)
    async def http_exception_handler(_request, exc):
        if "WWW-Authenticate" in exc.headers:
            return PlainTextResponse(
                f"{security.realm}: {exc.detail}",
                status_code=exc.status_code,
                headers=exc.headers,
            )
        return JSONResponse(
            {"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers
        )

    async def check_basic_auth(credentials: HTTPBasicCredentials = Depends(security)):
        """Check basic access authentication if username and passwort are set."""
        # checking user and password while avoiding timing attacks
        user_ok = secrets.compare_digest(credentials.username, user)
        pwd_ok = secrets.compare_digest(credentials.password, pwd)
        if not (user_ok and pwd_ok):
            www_auth = f'Basic realm="{security.realm}"'
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": www_auth},
            )

    return Depends(check_basic_auth)
