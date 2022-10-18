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
#

"""Create signing keys for development"""

from pathlib import Path

from jwcrypto import jwk

REPO_ROOT_DIR = Path(__file__).parent.parent.resolve()
ENV_FILE = REPO_ROOT_DIR / ".devcontainer" / "auth_keys.env"


def generate_jwk() -> jwk.JWK:
    """Generate a random EC based JWK."""
    return jwk.JWK.generate(kty="EC", crv="P-256")


def generate_external_keys():
    """Create external key set (with private keys)."""
    external_jwks = jwk.JWKSet()
    external_jwk = generate_jwk()
    external_jwk["kid"] = "test"
    external_jwks.add(external_jwk)
    return external_jwks.export(private_keys=True)


def generate_internal_keys():
    """Create internal key pair."""
    internal_jwk = generate_jwk()
    return internal_jwk.export(private_key=True)


def run():
    """Create local env file with signing keys"""
    if ENV_FILE.exists():
        print("Local env file already exists.")
        return
    print("Creating random signing keys...")
    external_keys = generate_external_keys()
    internal_keys = generate_internal_keys()
    with open(ENV_FILE, "w", encoding="utf-8") as env_file:
        env_file.write(f"AUTH_SERVICE_AUTH_INT_KEYS={internal_keys!r}\n")
        env_file.write(f"AUTH_SERVICE_AUTH_EXT_KEYS={external_keys!r}\n")
    print("Local env file has been created.")


if __name__ == "__main__":
    run()
