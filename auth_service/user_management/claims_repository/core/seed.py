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

"""
Functions to seed the repository with user claims.
"""

import logging

from hexkit.protocols.dao import MultipleHitsFoundError, NoHitsFoundError

from auth_service.config import Config
from auth_service.deps import get_mongodb_config, get_mongodb_dao_factory
from auth_service.user_management.claims_repository.core.claims import (
    create_data_steward_claim,
)
from auth_service.user_management.claims_repository.core.utils import is_data_steward
from auth_service.user_management.claims_repository.deps import (
    get_claim_dao,
    get_claim_dao_factory,
    get_claim_dao_factory_config,
)
from auth_service.user_management.user_registry.deps import (
    get_user_dao,
    get_user_dao_factory,
    get_user_dao_factory_config,
)

__all__ = ["seed_claims"]

log = logging.getLogger(__name__)


async def seed_claims(config: Config) -> None:
    """Seed the claims repository with claims specified in the config."""
    data_stewards = config.add_as_data_stewards
    if not data_stewards:
        return
    user_dao = await get_user_dao(
        dao_factory=get_user_dao_factory(
            config=get_user_dao_factory_config(config),
            dao_factory=get_mongodb_dao_factory(config=get_mongodb_config(config)),
        )
    )
    claim_dao = await get_claim_dao(
        dao_factory=get_claim_dao_factory(
            config=get_claim_dao_factory_config(config),
            dao_factory=get_mongodb_dao_factory(config=get_mongodb_config(config)),
        )
    )
    for data_steward in data_stewards:
        try:
            user = await user_dao.find_one(mapping={"ext_id": data_steward})
        except (NoHitsFoundError, MultipleHitsFoundError):
            log.warning("Data steward %r not found in user registry", data_steward)
            continue
        if await is_data_steward(user.id, user_dao, claim_dao):
            log.debug(
                "Data steward %r already added to the claims repository", data_steward
            )
            continue
        claim = create_data_steward_claim(user.id)
        await claim_dao.insert(claim)
        log.info("Data steward %r added to the claims repository", data_steward)
