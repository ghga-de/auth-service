#!/usr/bin/env python3

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

"""Generate a JSON schema from the service's Config class.
"""

import importlib
import json
import subprocess
from pathlib import Path
from typing import Any, Type

import yaml
from pydantic import BaseSettings
from typer import Typer

HERE = Path(__file__).parent.resolve()
DEV_CONFIG_YAML = HERE.parent.resolve() / ".devcontainer" / ".dev_config.yaml"
GET_PACKAGE_NAME_SCRIPT = HERE / "get_package_name.py"

cli = Typer()


def get_config_class() -> Type[BaseSettings]:
    """
    Dynamically imports and returns the Config class from the current service.
    This makes the script service repo agnostic.
    """
    # get the name of the microservice package
    with subprocess.Popen(
        args=[GET_PACKAGE_NAME_SCRIPT],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as process:
        assert (
            process.wait() == 0 and process.stdout is not None
        ), "Failed to get package name."
        package_name = process.stdout.read().decode("utf-8").strip("\n")

    # import the Config class from the microservice package:
    config_module: Any = importlib.import_module(f"{package_name}.config")
    config_class = config_module.Config

    return config_class


def get_dev_config():
    """Get dev config object."""
    config_class = get_config_class()
    return config_class(config_yaml=DEV_CONFIG_YAML)


@cli.command()
def print_schema():
    """Prints a JSON schema generated from a Config class."""
    config = get_dev_config()
    print(config.schema_json(indent=2))


@cli.command()
def print_example():
    """Prints an example config yaml."""
    config = get_dev_config()
    normalized_config_dict = json.loads(config.json())
    print(yaml.dump(normalized_config_dict).rstrip())


if __name__ == "__main__":
    cli()
