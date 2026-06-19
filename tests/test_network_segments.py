from __future__ import annotations

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.routes.network_segments import NetworkSegmentCreate, create_network_segment


def test_network_segment_create_schema() -> None:
    # Valid schema payload
    payload = NetworkSegmentCreate(
        name="LAN",
        cidr="192.168.1.0/24",
        description="Local LAN",
        vlan_id=10,
        is_active=True,
        scan_enabled=True,
    )
    assert payload.name == "LAN"
    assert payload.cidr == "192.168.1.0/24"

    # Missing name
    with pytest.raises(ValidationError):
        NetworkSegmentCreate(cidr="192.168.1.0/24")  # type: ignore[call-arg]

    # Missing cidr
    with pytest.raises(ValidationError):
        NetworkSegmentCreate(name="LAN")  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_create_network_segment_validation() -> None:
    # Test invalid CIDR format
    invalid_payload = NetworkSegmentCreate(
        name="LAN",
        cidr="invalid-cidr",
        description="Local LAN",
    )

    # Mocking DB session is not needed to hit the validation step
    # because the ipaddress validation happens first.
    with pytest.raises(HTTPException) as exc_info:
        await create_network_segment(
            segment=invalid_payload,
            db=None,  # type: ignore[arg-type]
            _user=None,  # type: ignore[arg-type]
        )
    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == "Invalid CIDR format"
