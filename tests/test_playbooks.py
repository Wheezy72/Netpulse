from __future__ import annotations

import pytest
from app.core.config import Settings
from unittest.mock import MagicMock


class TestPrebuiltPlaybooks:
    """Validate registration and basic behavior of the new prebuilt playbooks."""

    def test_playbooks_registered(self):
        settings = Settings()
        assert "broadcast_storm_mitigation.py" in settings.allowed_prebuilt_scripts
        assert "rogue_dhcp_mitigation.py" in settings.allowed_prebuilt_scripts
        assert "bgp_peer_isolation.py" in settings.allowed_prebuilt_scripts

    @pytest.mark.asyncio
    async def test_broadcast_storm_simulation(self):
        # Create a mock execution context
        ctx = MagicMock()
        ctx.params = {
            "mac_address": "00:11:22:33:44:55",
            "switch_host": "192.168.1.100",
        }
        ctx.logger = MagicMock()
        ctx.db = MagicMock()

        # Import the script's run function directly
        from scripts.prebuilt.broadcast_storm_mitigation import run
        res = await run(ctx)

        assert res["status"] == "simulated"
        assert res["mac_address"] == "00:11:22:33:44:55"
        assert res["switch_host"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_rogue_dhcp_simulation(self):
        ctx = MagicMock()
        ctx.params = {
            "rogue_ip": "192.168.1.99",
            "switch_host": "192.168.1.100",
        }
        ctx.logger = MagicMock()
        ctx.db = MagicMock()

        from scripts.prebuilt.rogue_dhcp_mitigation import run
        res = await run(ctx)

        assert res["status"] == "simulated"
        assert res["rogue_ip"] == "192.168.1.99"
        assert res["switch_host"] == "192.168.1.100"

    @pytest.mark.asyncio
    async def test_bgp_peer_isolation_simulation(self):
        ctx = MagicMock()
        ctx.params = {
            "peer_ip": "198.51.100.2",
            "asn": 65000,
            "router_host": "192.168.1.1",
        }
        ctx.logger = MagicMock()
        ctx.db = MagicMock()

        from scripts.prebuilt.bgp_peer_isolation import run
        res = await run(ctx)

        assert res["status"] == "simulated"
        assert res["peer_ip"] == "198.51.100.2"
        assert res["router_host"] == "192.168.1.1"
