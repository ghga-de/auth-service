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

"""Test upload access API functionality"""

from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi import status
from hexkit.utils import now_utc_ms_prec

from auth_service.user_registry.deps import get_iva_dao, get_user_dao
from auth_service.user_registry.models.ivas import Iva, IvaState, IvaType
from tests.fixtures.constants import ID_OF_JOHN

from ...fixtures.utils import DummyIvaDao, DummyUserDao
from .fixtures import FullClient, fixture_full_client  # noqa: F401

pytestmark = pytest.mark.asyncio()

UNVERIFIED_IVA_ID = uuid4()
UNVERIFIED_IVA = Iva(
    id=UNVERIFIED_IVA_ID,
    user_id=ID_OF_JOHN,
    value="(0123)456789",
    type=IvaType.PHONE,
    state=IvaState.UNVERIFIED,
    created=now_utc_ms_prec(),
    changed=now_utc_ms_prec(),
)

VERIFIED_IVA_ID = uuid4()
VERIFIED_IVA = Iva(
    id=VERIFIED_IVA_ID,
    user_id=ID_OF_JOHN,
    value="(0123)456789",
    type=IvaType.PHONE,
    state=IvaState.VERIFIED,
    created=now_utc_ms_prec(),
    changed=now_utc_ms_prec(),
)

# Test data for upload box claims
TEST_BOX_ID = UUID("cfeac7d0-bc58-4d00-975d-850c190c10a1")
UPLOAD_BOX_CLAIM_DATA = {
    "visa_type": "https://www.ghga.de/GA4GH/VisaTypes/Upload/v1.0",
    "visa_value": f"https://ghga.de/uploads/{TEST_BOX_ID}",
    "source": "https://ghga.de",
    "assertion_date": "2025-11-30T12:00:00Z",
    "asserted_by": "dac",  # TODO: who asserts the claim?
}


async def test_grant_upload_access(full_client: FullClient):
    """Test granting upload access to a box."""
    user_dao = DummyUserDao()
    full_client.app.dependency_overrides[get_user_dao] = lambda: user_dao
    now = now_utc_ms_prec()
    iva_dao = DummyIvaDao([VERIFIED_IVA])
    full_client.app.dependency_overrides[get_iva_dao] = lambda: iva_dao

    validity = {
        "valid_from": f"{now.year - 1}-01-01T00:00:00Z",
        "valid_until": f"{now.year + 1}-12-31T23:59:59Z",
    }

    # Try with an invalid box ID (i.e. something that isn't a UUID4)
    response = await full_client.post(
        f"/upload-access/users/{ID_OF_JOHN}/ivas/{VERIFIED_IVA_ID}/boxes/box123",
        json=validity,
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Now use a proper UUID4 ID
    box_id = uuid4()
    response = await full_client.post(
        f"/upload-access/users/{ID_OF_JOHN}/ivas/{VERIFIED_IVA_ID}/boxes/{box_id}",
        json=validity,
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT


async def test_check_upload_access(full_client: FullClient):
    """Test checking upload access for a single box."""
    user_dao = DummyUserDao()
    full_client.app.dependency_overrides[get_user_dao] = lambda: user_dao
    now = now_utc_ms_prec()
    iva_dao = DummyIvaDao([VERIFIED_IVA])
    full_client.app.dependency_overrides[get_iva_dao] = lambda: iva_dao

    # First grant upload access
    claim_data: dict[str, Any] = {
        "valid_from": now.isoformat(),
        "valid_until": (now + timedelta(days=60)).isoformat(),
    }

    url = (
        f"/upload-access/users/{ID_OF_JOHN}/ivas/{VERIFIED_IVA_ID}/boxes/{TEST_BOX_ID}"
    )
    response = await full_client.post(url, json=claim_data)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # Now check upload access
    response = await full_client.get(
        f"/upload-access/users/{ID_OF_JOHN}/boxes/{TEST_BOX_ID}"
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() is not None

    # Call the endpoint with an invalid box ID to verify that typing is set right
    response = await full_client.get(
        f"/upload-access/users/{ID_OF_JOHN}/boxes/some-string"
    )
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Check access for non-existent box
    response = await full_client.get(
        f"/upload-access/users/{ID_OF_JOHN}/boxes/{uuid4()}"
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() is None


async def test_get_boxes_with_upload_access(full_client: FullClient):
    """Test getting all boxes with upload access for a user."""
    user_dao = DummyUserDao()
    full_client.app.dependency_overrides[get_user_dao] = lambda: user_dao
    now = now_utc_ms_prec()
    iva_dao = DummyIvaDao([VERIFIED_IVA])
    full_client.app.dependency_overrides[get_iva_dao] = lambda: iva_dao

    # Grant upload access to multiple boxes
    box1 = str(uuid4())
    box2 = str(uuid4())
    claim_data: dict[str, Any] = {
        "valid_from": now.isoformat(),
        "valid_until": (now + timedelta(days=60)).isoformat(),
    }

    for box_id in [box1, box2]:
        url = f"/upload-access/users/{ID_OF_JOHN}/ivas/{VERIFIED_IVA_ID}/boxes/{box_id}"
        response = await full_client.post(url, json=claim_data)
        assert response.status_code == status.HTTP_204_NO_CONTENT

    # Get list of accessible boxes
    response = await full_client.get(f"/upload-access/users/{ID_OF_JOHN}/boxes")
    assert response.status_code == status.HTTP_200_OK
    boxes = response.json()
    assert isinstance(boxes, dict)
    assert len(boxes) == 2
    assert box1 in boxes
    assert box2 in boxes


async def test_get_upload_access_grants(full_client: FullClient):
    """Test getting upload access grants."""
    user_dao = DummyUserDao()
    full_client.app.dependency_overrides[get_user_dao] = lambda: user_dao
    now = now_utc_ms_prec()
    iva_dao = DummyIvaDao([VERIFIED_IVA])
    full_client.app.dependency_overrides[get_iva_dao] = lambda: iva_dao

    # Create an upload access claim
    claim_data: dict[str, Any] = {
        "valid_from": now.isoformat(),
        "valid_until": (now + timedelta(days=60)).isoformat(),
    }

    url = (
        f"/upload-access/users/{ID_OF_JOHN}/ivas/{VERIFIED_IVA_ID}/boxes/{TEST_BOX_ID}"
    )
    response = await full_client.post(url, json=claim_data)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # Get upload access grants
    response = await full_client.get("/upload-access/grants")
    assert response.status_code == status.HTTP_200_OK
    grants = response.json()
    assert isinstance(grants, list)
    assert len(grants) >= 1

    grant = grants[0]
    assert grant["user_id"] == str(ID_OF_JOHN)
    assert grant["iva_id"] == str(VERIFIED_IVA_ID)
    assert grant["box_id"] == str(TEST_BOX_ID)
    assert "user_name" in grant
    assert "user_email" in grant


async def test_grant_upload_access_with_unverified_iva(full_client: FullClient):
    """Test granting upload access to a box when the IVA is not yet verified."""
    user_dao = DummyUserDao()
    full_client.app.dependency_overrides[get_user_dao] = lambda: user_dao
    now = now_utc_ms_prec()
    iva_dao = DummyIvaDao([UNVERIFIED_IVA])
    full_client.app.dependency_overrides[get_iva_dao] = lambda: iva_dao

    validity = {
        "valid_from": now.isoformat(),
        "valid_until": (now + timedelta(hours=12)).isoformat(),
    }

    # Grant access with an unverified IVA
    response = await full_client.post(
        f"/upload-access/users/{ID_OF_JOHN}/ivas/{UNVERIFIED_IVA_ID}/boxes/{TEST_BOX_ID}",
        json=validity,
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # Retrieve the test user's claims, which should have the one we just added
    response = await full_client.get(f"/users/{ID_OF_JOHN}/claims")
    assert response.status_code == status.HTTP_200_OK
    requested_claims = response.json()

    assert len(requested_claims) == 1
    claim_data = requested_claims[0]
    assert claim_data["user_id"] == str(ID_OF_JOHN)
    assert claim_data["iva_id"] == str(UNVERIFIED_IVA_ID)

    # Check if the user has access to the test box -- they shouldn't
    response = await full_client.get(
        f"/upload-access/users/{ID_OF_JOHN}/boxes/{TEST_BOX_ID}"
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() is None

    response = await full_client.get(f"/upload-access/users/{ID_OF_JOHN}/boxes")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {}


async def test_grant_upload_access_without_iva(full_client: FullClient):
    """Test granting upload access to a box when the IVA does not exist."""
    user_dao = DummyUserDao()
    full_client.app.dependency_overrides[get_user_dao] = lambda: user_dao
    iva_dao = DummyIvaDao()
    full_client.app.dependency_overrides[get_iva_dao] = lambda: iva_dao

    now = now_utc_ms_prec()
    validity = {
        "valid_from": now.isoformat(),
        "valid_until": (now + timedelta(weeks=4)).isoformat(),
    }

    response = await full_client.post(
        f"/upload-access/users/{ID_OF_JOHN}/ivas/{VERIFIED_IVA_ID}/boxes/{TEST_BOX_ID}",
        json=validity,
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["detail"] == "The IVA was not found."

    response = await full_client.get(f"/users/{ID_OF_JOHN}/claims")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == []

    response = await full_client.get(
        f"/upload-access/users/{ID_OF_JOHN}/boxes/{TEST_BOX_ID}"
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() is None

    response = await full_client.get(f"/upload-access/users/{ID_OF_JOHN}/boxes")
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {}


async def test_check_upload_access_with_unverified_iva(full_client: FullClient):
    """Test checking upload access for a single box with an unverified IVA."""
    user_dao = DummyUserDao()
    full_client.app.dependency_overrides[get_user_dao] = lambda: user_dao
    now = now_utc_ms_prec()
    iva_dao = DummyIvaDao([UNVERIFIED_IVA])
    full_client.app.dependency_overrides[get_iva_dao] = lambda: iva_dao

    # post valid upload access permission for VERIFIED_IVA_ID and box123
    now = now_utc_ms_prec()
    validity = {
        "valid_from": now.isoformat(),
        "valid_until": (now + timedelta(weeks=4)).isoformat(),
    }

    url = f"/upload-access/users/{ID_OF_JOHN}/ivas/{UNVERIFIED_IVA_ID}/boxes/{TEST_BOX_ID}"
    response = await full_client.post(url, json=validity)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # check that access is not given when the IVA is not verified
    response = await full_client.get(
        f"/upload-access/users/{ID_OF_JOHN}/boxes/{TEST_BOX_ID}"
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() is None
