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

"""Test the core TOTP functionality."""

import base64
import hashlib
from datetime import timedelta

from ghga_service_commons.utils.utc_dates import now_as_utc
from pydantic import SecretStr
from pytest import fixture, mark

from auth_service.auth_adapter.core.totp import TOTPAlgorithm, TOTPConfig, TOTPHandler


@fixture(name="totp_handler")
def create_totp_handler() -> TOTPHandler:
    """Create a default TOTP handler."""
    encryption_key = TOTPHandler.random_encryption_key()
    config = TOTPConfig(totp_encryption_key=SecretStr(encryption_key))
    return TOTPHandler(config)


@fixture(name="custom_totp_handler")
def create_custom_totp_handler() -> TOTPHandler:
    """Create a non-default TOTP handler."""
    encryption_key = TOTPHandler.random_encryption_key()
    config = TOTPConfig(
        totp_algorithm=TOTPAlgorithm.SHA512,
        totp_digits=8,
        totp_interval=20,
        totp_tolerance=0,
        totp_attempts=1,
        totp_secret_size=64,
        totp_encryption_key=SecretStr(encryption_key),
    )
    return TOTPHandler(config)


def test_random_encryption_keys():
    """Test that encryption keys can be randomly generated."""
    key = TOTPHandler.random_encryption_key()
    assert isinstance(key, str)
    decoded = base64.b64decode(key)
    assert len(decoded) == 32


def test_default_parameters(totp_handler: TOTPHandler):
    """Check that the default TOTP handler has the expected parameters."""
    assert totp_handler.digest is hashlib.sha1
    assert totp_handler.digits == 6
    assert totp_handler.interval == 30
    assert totp_handler.tolerance == 1
    assert totp_handler.max_attempts == 3
    assert totp_handler.secret_size == 32


def test_generate_token(totp_handler: TOTPHandler):
    """Test generating a TOTP token."""
    token = totp_handler.generate_token()
    secret = token.secret.get_secret_value()
    decoded_secret = base64.b64decode(secret)
    assert len(decoded_secret) == 72
    assert token.counter == -1
    assert token.attempts == -1


def test_get_secret(totp_handler: TOTPHandler):
    """Test generating a TOTP token."""
    token = totp_handler.generate_token()
    secret = totp_handler.get_secret(token)
    assert isinstance(secret, str)
    assert len(secret) == 32
    assert secret.isalnum()


def test_generate_code(totp_handler: TOTPHandler):
    """Test generating a TOTP code."""
    token = totp_handler.generate_token()
    code = totp_handler.generate_code(token)
    assert isinstance(code, str)
    assert len(code) == 6
    assert isinstance(int(code), int)


def test_verify_code_with_valid_code(totp_handler: TOTPHandler):
    """Test verification of a valid TOTP code."""
    token = totp_handler.generate_token()
    for_time = now_as_utc()
    code = totp_handler.generate_code(token, for_time)
    assert totp_handler.verify_code(token, code, for_time) is True


def test_token_object_is_modified(totp_handler: TOTPHandler):
    """Test modification of token object after verification."""
    token = totp_handler.generate_token()
    secret = token.secret
    assert token.attempts == -1
    assert token.counter == -1
    token.attempts = 1
    token.counter = 0
    for_time = now_as_utc()
    verified = totp_handler.verify_code(token, "123456", for_time)
    assert token.secret == secret
    expected_attempts = -1 if verified else 1
    assert token.attempts == expected_attempts
    assert token.counter > 0


def test_verify_code_with_slightly_invalid_code(totp_handler: TOTPHandler):
    """Test verification of a slightly invalid TOTP code.

    Allows one false positive caused by hash collisions with limited code range.
    """
    token = totp_handler.generate_token()
    for_time = now_as_utc()
    code = totp_handler.generate_code(token, for_time)
    false_positives = 0
    for i in range(6):
        for j in range(10):
            changed_digit = str((int(code[i]) + j) % 10)
            code = code[:i] + changed_digit + code[i + 1 :]
            verified = totp_handler.verify_code(token, code, for_time)
            assert verified is None or verified is False or verified is True
            if verified:
                false_positives += 1
    assert false_positives < 2


@mark.parametrize(
    "code",
    [
        "",
        "123",
        "12345",
        "1234567",
        "123456789",
        "-23456",
        "123?56",
        "12345x",
        "abcdef",
    ],
)
def test_verify_code_with_totally_invalid_code(code: str, totp_handler: TOTPHandler):
    """Test verification of a totally invalid TOTP code."""
    token = totp_handler.generate_token()
    assert token.attempts == -1
    assert token.counter == -1
    assert totp_handler.verify_code(token, code) is None
    assert token.attempts == -1
    assert token.counter == -1


def test_verification_with_time_in_the_past(totp_handler: TOTPHandler):
    """Test that going back in time during validation is rejected."""
    token = totp_handler.generate_token()
    for_time = now_as_utc()
    code = totp_handler.generate_code(token, for_time)
    assert totp_handler.verify_code(token, code, for_time) is True
    for_time -= timedelta(seconds=totp_handler.interval * 3)
    code = totp_handler.generate_code(token, for_time)
    assert totp_handler.verify_code(token, code, for_time) is None


def test_verification_with_time_in_the_future(totp_handler: TOTPHandler):
    """Test that going forward in time during validation is allowed."""
    token = totp_handler.generate_token()
    for_time = now_as_utc()
    code = totp_handler.generate_code(token, for_time)
    assert totp_handler.verify_code(token, code, for_time) is True
    for_time += timedelta(seconds=totp_handler.interval * 3)
    code = totp_handler.generate_code(token, for_time)
    assert totp_handler.verify_code(token, code, for_time) is True


def test_replay_attack(totp_handler: TOTPHandler):
    """Test that replay attacks are rejected."""
    token = totp_handler.generate_token()
    for_time = now_as_utc()
    code = totp_handler.generate_code(token, for_time)
    assert totp_handler.verify_code(token, code, for_time) is True
    assert totp_handler.verify_code(token, code, for_time) is None


def test_brute_force_attack(totp_handler: TOTPHandler):
    """Test that brute force attacks are rejected.

    Allows one false positive caused by hash collisions with limited code range.
    """
    for_time = now_as_utc()
    for runs in range(2):
        token = totp_handler.generate_token()
        code = totp_handler.generate_code(token, for_time)

        for j in range(totp_handler.max_attempts):
            invalid_code = code[:-1] + str((int(code[-1]) + j + 1) % 10)
            verified = totp_handler.verify_code(token, invalid_code, for_time)
            if verified is True:
                if runs > 1:
                    assert False, "Too many false positives"
            else:
                assert verified is False, "Brute force attack detected too early"

        verified = totp_handler.verify_code(token, code, for_time)
        assert verified is None, "Brute force attack not detected"


def test_verification_inside_tolerance_interval(totp_handler: TOTPHandler):
    """Test verification of a valid code inside the tolerance interval.

    Allows some false positives caused by hash collisions with limited code range.
    """
    tolerance = totp_handler.tolerance
    for_time = now_as_utc()
    overrun = 100
    false_positives = 0
    for offset in range(-tolerance - overrun, tolerance + overrun + 1):
        token = totp_handler.generate_token()
        code = totp_handler.generate_code(token, for_time, offset)
        verified = totp_handler.verify_code(token, code, for_time)
        assert verified is False or verified is True
        if abs(offset) <= tolerance:
            assert verified
        elif verified:
            false_positives += 1
    assert false_positives < overrun / 1000


def test_custom_parameters(custom_totp_handler: TOTPHandler):
    """Check that the custom TOTP handler has the expected parameters."""
    handler = custom_totp_handler
    assert handler.digest is hashlib.sha512
    assert handler.digits == 8
    assert handler.interval == 20
    assert handler.tolerance == 0
    assert handler.max_attempts == 1
    assert handler.secret_size == 64


def test_get_custom_secret(custom_totp_handler: TOTPHandler):
    """Test generating a custom TOTP token."""
    token = custom_totp_handler.generate_token()
    secret = custom_totp_handler.get_secret(token)
    assert isinstance(secret, str)
    assert len(secret) == 64
    assert secret.isalnum()


def test_verify_with_custom_handler(custom_totp_handler: TOTPHandler):
    """Test verification of a valid TOTP code using a custom handler."""
    token = custom_totp_handler.generate_token()
    for_time = now_as_utc()
    code = custom_totp_handler.generate_code(token, for_time)
    assert len(code) == 8
    assert custom_totp_handler.verify_code(token, code, for_time) is True
    assert custom_totp_handler.verify_code(token, code, for_time) is None
