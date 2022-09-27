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

"""Config Parameter Modeling and Parsing"""

import logging.config
from typing import Optional

from pydantic import root_validator

from ghga_service_chassis_lib.api import ApiConfigBase, LogLevel
from ghga_service_chassis_lib.config import config_from_yaml


def configure_logging():
    """Configure the application logging.

    This must happen before the application is configured.
    """
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "()": "uvicorn.logging.DefaultFormatter",
                    "fmt": "%(levelprefix)s %(asctime)s %(name)s: %(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                },
            },
            "handlers": {
                "default": {
                    "formatter": "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stderr",
                },
            },
            "loggers": {
                "metadata_repository_service": {
                    "handlers": ["default"],
                    "level": CONFIG.log_level.upper(),
                },
            },
        }
    )


@config_from_yaml(prefix="auth_service")
class Config(ApiConfigBase):
    """Config parameters and their defaults."""

    service_name: str = "auth_service"
    log_level: LogLevel = "debug"
    run_auth_adapter: bool = False
    auth_path_prefix: str = "/auth"
    basic_auth_users: Optional[list[str]] = None
    basic_auth_pwds: Optional[list[str]] = None
    basic_auth_realm: Optional[str] = "GHGA Data Portal"
    db_url: str = "mongodb://localhost:27017"
    db_name: str = "user-registry"
    user_collection: str = "users"

    
    @root_validator
    def check_credentials_match(cls, values):
        """Check if basic_auth_users and basic_auth_pwds match."""
        
        users, pws = values.get('basic_auth_user'), values.get('basic_auth_pwd')
        if users is None:
            if pws is not None:
                raise ValueError(
                    'If basic_auth_users is None, basic_auth_pwds should also be None.'
                )
        else:
            if len(users) != len(pws):
               raise ValueError(
                    'If specified, basic_auth_users and basic_auth_pwds must be of' +
                    ' the same length.'
                )
        return values


CONFIG = Config()
