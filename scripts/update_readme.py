#!/usr/bin/env python3

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

"""Generate documentation for this package using different sources."""

import json
import subprocess  # nosec
import sys
import tomllib
from pathlib import Path
from string import Template

import jsonschema2md
from casefy import kebabcase, titlecase
from pydantic import BaseModel, Field

from script_utils.cli import echo_failure, echo_success, run

ROOT_DIR = Path(__file__).parent.parent.resolve()
PYPROJECT_TOML_PATH = ROOT_DIR / "pyproject.toml"
README_GENERATION_DIR = ROOT_DIR / ".readme_generation"
TEMPLATE_OVERVIEW_PATH = README_GENERATION_DIR / "template_overview.md"
DESCRIPTION_PATH = README_GENERATION_DIR / "description.md"
DESIGN_PATH = README_GENERATION_DIR / "design.md"
README_TEMPLATE_PATH = README_GENERATION_DIR / "readme_template.md"
CONFIG_SCHEMA_PATH = ROOT_DIR / "config_schema.json"
OPENAPI_YAML_REL_PATH = "./openapi.yaml"
README_PATH = ROOT_DIR / "README.md"


class PackageHeader(BaseModel):
    """A basic summary of a package."""

    shortname: str = Field(
        ...,
        description=(
            "The abbreviation of the package name. Is identical to the package name."
        ),
    )
    version: str = Field(..., description="The version of the package.")
    summary: str = Field(
        ..., description="A short 1 or 2 sentence summary of the package."
    )


class PackageName(BaseModel):
    """The name of a package and it's different representations."""

    repo_name: str = Field(..., description="The name of the repo")
    name: str = Field(..., description="The full name of the package in kebab case.")
    title: str = Field(..., description="The name of the package formatted as title.")


class PackageDetails(PackageHeader, PackageName):
    """A container for details on a package used to build documentation."""

    description: str = Field(
        ..., description="A markdown-formatted description of the package."
    )
    design_description: str = Field(
        ...,
        description=(
            "A markdown-formatted description of overall architecture and design of"
            + " the package."
        ),
    )
    config_description: str = Field(
        ...,
        description=(
            "A markdown-formatted list of all configuration parameters of this package."
        ),
    )
    openapi_doc: str = Field(
        ...,
        description=(
            "A markdown-formatted description rendering or linking to an OpenAPI"
            " specification of the package."
        ),
    )


def read_toml_package_header() -> PackageHeader:
    """Read basic information about the package from the pyproject.toml"""

    with open(PYPROJECT_TOML_PATH, "rb") as pyproject_toml:
        pyproject = tomllib.load(pyproject_toml)
        pyproject_project = pyproject["project"]
        return PackageHeader(
            shortname=pyproject_project["name"],
            version=pyproject_project["version"],
            summary=pyproject_project["description"],
        )


def read_package_name() -> PackageName:
    """Infer the package name from the name of the git origin."""

    with subprocess.Popen(
        args="basename -s .git `git config --get remote.origin.url`",
        cwd=ROOT_DIR,
        stdout=subprocess.PIPE,
        shell=True,
    ) as process:
        stdout, _ = process.communicate()

    if not stdout:
        raise RuntimeError("The name of the git origin could not be resolved.")
    git_origin_name = stdout.decode("utf-8").strip()

    repo_name = kebabcase(git_origin_name)
    name = (
        "my-microservice"
        if repo_name == "microservice-repository-template"
        else repo_name
    )
    title = titlecase(name)

    return PackageName(repo_name=repo_name, name=name, title=title)


def read_template_overview() -> str:
    """Read the template_overview."""

    return TEMPLATE_OVERVIEW_PATH.read_text()


def read_package_description() -> str:
    """Read the package description."""

    return DESCRIPTION_PATH.read_text()


def read_design_description() -> str:
    """Read the design description."""

    return DESIGN_PATH.read_text()


def generate_config_docs() -> str:
    """Generate markdown-formatted documentation for the configration parameters
    listed in the config schema."""

    parser = jsonschema2md.Parser(
        examples_as_yaml=False,
        show_examples="all",
    )
    with open(CONFIG_SCHEMA_PATH, encoding="utf-8") as json_file:
        config_schema = json.load(json_file)

    md_lines = parser.parse_schema(config_schema)

    # ignore everything before the properties header:
    properties_index = md_lines.index("## Properties\n\n")
    md_lines = md_lines[properties_index + 1 :]

    return "\n".join(md_lines)


def generate_openapi_docs() -> str:
    """Generate markdown-formatted documentation linking to or rendering an OpenAPI
    specification of the package. If no OpenAPI specification is present, return an
    empty string."""

    open_api_yaml_path = ROOT_DIR / OPENAPI_YAML_REL_PATH

    if not open_api_yaml_path.exists():
        return ""

    return (
        "## HTTP API\n"
        + "An OpenAPI specification for this service can be found"
        + f" [here]({OPENAPI_YAML_REL_PATH})."
    )


def get_package_details() -> PackageDetails:
    """Get details required to build documentation for the package."""

    header = read_toml_package_header()
    name = read_package_name()
    description = read_package_description()
    config_description = generate_config_docs()
    return PackageDetails(
        **header.model_dump(),
        **name.model_dump(),
        description=description,
        config_description=config_description,
        design_description=read_design_description(),
        openapi_doc=generate_openapi_docs(),
    )


def generate_single_readme(*, details: PackageDetails) -> str:
    """Generate a single markdown-formatted readme file for the package based on the
    provided details."""

    template_content = README_TEMPLATE_PATH.read_text()
    template = Template(template_content)
    return template.substitute(details.model_dump())


def main(check: bool = False) -> None:
    """Update the readme markdown."""

    details = get_package_details()
    readme_content = generate_single_readme(details=details)

    if details.repo_name == "microservice-repository-template":
        template_overview = read_template_overview()
        readme_content = template_overview + readme_content

    if check:
        if README_PATH.read_text() != readme_content:
            echo_failure("README.md is not up to date.")
            sys.exit(1)
        echo_success("README.md is up to date.")
        return

    README_PATH.write_text(readme_content)
    echo_success("Successfully updated README.md.")


if __name__ == "__main__":
    run(main)
