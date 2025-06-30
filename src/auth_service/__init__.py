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

"""Auth Service

The GHGA auth service contains all services needed for the management,
authentication and authorization of users.
"""

from importlib.metadata import version

__version__ = version(__package__)

VERSION = __version__
TITLE = "Auth Service API"
DESCRIPTION = "REST API for managing the GHGA users and user claims"

# TO DO: the URLs cannot be converted to YAML (openapi_from_app)

CONTACT = {
    "name": "GHGA",
    # "url": "https://www.ghga.de/about-us/contact",
    "email": "helpdesk@ghga.de",
}

LICENSE_INFO = {
    "name": "Apache 2.0",
    # "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
}

TAGS_METADATA = [
    {"name": "users", "description": "User data"},
    {"name": "totp", "description": "TOTP tokens"},
    {"name": "claims", "description": "User claims"},
    {"name": "access", "description": "Access permissions"},
]
