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

"""Used to define the location of the main FastAPI app object."""

import sys
from pathlib import Path

from fastapi import FastAPI

from auth_service import (
    CONTACT,
    DESCRIPTION,
    LICENSE_INFO,
    TAGS_METADATA,
    TITLE,
    VERSION,
)

__all__ = ["app"]

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tests.fixtures.auth_keys import reload_auth_key_config

reload_auth_key_config(False)

from auth_service.prepare import (
    access_router,
    base_router,
    claims_router,
    users_router,
)

app = FastAPI(
    title=TITLE,
    description=DESCRIPTION,
    version=VERSION,
    contact=CONTACT,
    license_info=LICENSE_INFO,
    openapi_tags=TAGS_METADATA,
)
app.include_router(base_router)
app.include_router(users_router)
app.include_router(claims_router)
app.include_router(access_router)
