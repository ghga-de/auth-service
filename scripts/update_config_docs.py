#!/usr/bin/env python3

# Copyright 2021 - 2026 Universität Tübingen, DKFZ, EMBL, and Universität zu Köln
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

"""Generate a JSON Schema from the service's Config class and an example
config YAML file, or check whether the existing files are up to date.
"""

import importlib
import json
import subprocess
import sys
from difflib import unified_diff
from pathlib import Path
from typing import Any

import yaml

from script_utils.cli import echo_failure, echo_success, run

HERE = Path(__file__).parent.resolve()
REPO_ROOT_DIR = HERE.parent
DEV_CONFIG_YAML = REPO_ROOT_DIR / ".devcontainer" / ".dev_config.yaml"
GET_PACKAGE_NAME_SCRIPT = HERE / "get_package_name.py"
EXAMPLE_CONFIG_YAML = REPO_ROOT_DIR / "example_config.yaml"
CONFIG_SCHEMA_JSON = REPO_ROOT_DIR / "config_schema.json"


class ValidationError(RuntimeError):
    """Raised when validation of config documentation fails."""


def get_config_class():
    """
    Dynamically imports and returns the Config class from the current service.
    This makes the script agnostic to the service repository.
    """
    # get the name of the microservice package
    with subprocess.Popen(
        args=[GET_PACKAGE_NAME_SCRIPT],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as process:
        assert process.wait() == 0 and process.stdout is not None, (
            "Failed to get package name."
        )
        package_name = process.stdout.read().decode("utf-8").strip("\n")

    # import the Config class from the microservice package:
    config_module: Any = importlib.import_module(f"{package_name}.config")
    config_class = config_module.Config

    return config_class


def get_dev_config():
    """Get dev config object."""
    config_class = get_config_class()
    return config_class(config_yaml=DEV_CONFIG_YAML)


def get_schema() -> str:
    """Returns a JSON schema generated from a Config class."""

    config = get_dev_config()
    schema_dict = type(config).model_json_schema()
    return json.dumps(schema_dict, indent=2)


def get_example() -> str:
    """Returns an example config YAML."""
    config = get_dev_config()
    normalized_config_dict = config.model_dump(mode="json", by_alias=True)
    return yaml.dump(normalized_config_dict, indent=2, sort_keys=True)


def update_docs():
    """Update the example config YAML and JSON Schema files documenting the
    config options.
    """
    EXAMPLE_CONFIG_YAML.write_text(get_example(), encoding="utf-8")
    CONFIG_SCHEMA_JSON.write_text(get_schema(), encoding="utf-8")


def print_diff(expected: str, observed: str):
    """Print differences between expected and observed example config YAML."""
    echo_failure("Differences in config YAML file:")
    for line in unified_diff(
        expected.splitlines(keepends=True),
        observed.splitlines(keepends=True),
        fromfile="expected",
        tofile="observed",
    ):
        print("   ", line.rstrip())


def check_docs():
    """Check whether the example config YAML and JSON Schema files are up to date.

    Raises:
        ValidationError: If not up to date.
    """

    example_expected = get_example()
    example_observed = EXAMPLE_CONFIG_YAML.read_text(encoding="utf-8")
    if example_expected != example_observed:
        print_diff(example_expected, example_observed)
        raise ValidationError(
            f"Example config YAML file at '{EXAMPLE_CONFIG_YAML}' is not up to date."
        )

    schema_expected = get_schema()
    schema_observed = CONFIG_SCHEMA_JSON.read_text(encoding="utf-8")
    if schema_expected != schema_observed:
        raise ValidationError(
            f"Config schema JSON file at '{CONFIG_SCHEMA_JSON}' is not up to date."
        )


def main(check: bool = False):
    """Update or check the config documentation files."""

    if check:
        try:
            check_docs()
        except ValidationError as error:
            echo_failure(f"Validation failed: {error}")
            sys.exit(1)
        echo_success("Config docs are up to date.")
        return

    update_docs()
    echo_success("Successfully updated the config docs.")


if __name__ == "__main__":
    run(main)
