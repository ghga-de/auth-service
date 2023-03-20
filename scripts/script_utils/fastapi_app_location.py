# Copyright 2021 - 2023 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

# pylint: skip-file

from tests.fixtures.auth_keys import reload_auth_key_config

__all__ = ["app"]

try:
    from auth_service.user_management.api.main import app
except Exception:
    # this needs to be fixed properly (no global config)
    reload_auth_key_config(False)
    from auth_service.user_management.api.main import app
