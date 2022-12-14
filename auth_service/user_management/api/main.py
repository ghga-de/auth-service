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
Module containing the main FastAPI router and (optionally) top-level API enpoints.
Additional endpoints might be structured in dedicated modules
(each of them having a sub-router).
"""

from fastapi import FastAPI, status
from ghga_service_chassis_lib.api import configure_app

from auth_service.config import CONFIG, configure_logging
from auth_service.user_management import (
    CONTACT,
    DESCRIPTION,
    LICENSE_INFO,
    TAGS_METADATA,
    TITLE,
    VERSION,
)
from auth_service.user_management.claims_repository.router import (
    router as claims_router,
)
from auth_service.user_management.user_registry.router import router as users_router

configure_logging()

app = FastAPI(
    title=TITLE,
    description=DESCRIPTION,
    version=VERSION,
    contact=CONTACT,
    license_info=LICENSE_INFO,
    openapi_tags=TAGS_METADATA,
)
configure_app(app, config=CONFIG)

app.include_router(users_router)
app.include_router(claims_router)


@app.get("/health", summary="health", tags=["health"], status_code=status.HTTP_200_OK)
async def health():
    """Used to check that this service is alive"""

    return {"status": "OK"}
