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
#

"""Helper dependencies for requiring authentication and authorization."""

from functools import partial
from typing import Annotated

from fastapi import Depends, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from ghga_service_commons.auth.ghga import (
    AuthContext,
    GHGAAuthContextProvider,
    has_role,
)
from ghga_service_commons.auth.policies import (
    require_auth_context_using_credentials,
)

from auth_service.config import CONFIG

__all__ = ["StewardAuthContext", "UserAuthContext"]


auth_provider = GHGAAuthContextProvider(config=CONFIG, context_class=AuthContext)


async def require_auth_context(
    credentials: Annotated[
        HTTPAuthorizationCredentials, Depends(HTTPBearer(auto_error=True))
    ],
) -> AuthContext:
    """Require a GHGA authentication and authorization context."""
    return await require_auth_context_using_credentials(credentials, auth_provider)


is_steward = partial(has_role, role="data_steward")


async def require_steward_context(
    credentials: Annotated[
        HTTPAuthorizationCredentials, Depends(HTTPBearer(auto_error=True))
    ],
) -> AuthContext:
    """Require a GHGA auth context with data steward role."""
    return await require_auth_context_using_credentials(
        credentials, auth_provider, is_steward
    )


## policy for requiring and getting an auth context
UserAuthContext = Annotated[AuthContext, Security(require_auth_context)]

# policy fo requiring and getting an auth context with data steward role
StewardAuthContext = Annotated[AuthContext, Security(require_steward_context)]
