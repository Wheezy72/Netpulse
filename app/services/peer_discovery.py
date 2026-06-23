from __future__ import annotations

import asyncio
import hmac
import hashlib
import json
import logging
import socket
import time
import uuid
from typing import Dict, Any

from sqlalchemy import select
from app.core.config import settings
from app.db.session import async_session_factory
from app.models.user import User, UserRole

logger = logging.getLogger("netpulse.peer_discovery")

UDP_PORT = 50080
INSTANCE_ID = str(uuid.uuid4())[:8]

def _sign_payload(payload: Dict[str, Any]) -> str:
    """Sign the JSON payload using the shared SECRET_KEY."""
    serialized = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hmac.new(settings.secret_key.encode("utf-8"), serialized, hashlib.sha256).hexdigest()

def _verify_signature(payload: Dict[str, Any], signature: str) -> bool:
    """Verify if the payload signature matches using the shared SECRET_KEY."""
    expected = _sign_payload(payload)
    return hmac.compare_digest(expected, signature)

async def check_is_admin_password_changed() -> bool:
    """Check if the admin password has been changed from the default 'changeme'."""
    try:
        async with async_session_factory() as session:
            result = await session.execute(select(User).where(User.username == settings.bootstrap_admin_username))
            user = result.scalar_one_or_none()
            if user:
                return not user.force_password_change
    except Exception as e:
        logger.error(f"Error checking admin password change status: {e}")
    return False

async def get_admin_hashed_password() -> str | None:
    """Retrieve the hashed password of the admin user."""
    try:
        async with async_session_factory() as session:
            result = await session.execute(select(User).where(User.username == settings.bootstrap_admin_username))
            user = result.scalar_one_or_none()
            if user:
                return user.hashed_password
    except Exception as e:
        logger.error(f"Error retrieving admin hashed password: {e}")
    return None

async def update_admin_password(hashed_password: str) -> bool:
    """Update the admin password and clear the force_password_change flag."""
    try:
        async with async_session_factory() as session:
            result = await session.execute(select(User).where(User.username == settings.bootstrap_admin_username))
            user = result.scalar_one_or_none()
            if user:
                user.hashed_password = hashed_password
                user.force_password_change = False
                await session.commit()
                logger.warning(f"Admin credentials synchronized and updated from peer. Force password change disabled.")
                return True
    except Exception as e:
        logger.error(f"Error updating admin password from peer: {e}")
    return False

class PeerDiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        super().__init__()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        logger.info(f"Peer discovery UDP socket bound to port {UDP_PORT}")

    def datagram_received(self, data: bytes, addr: tuple[str, int]):
        asyncio.create_task(self.handle_message(data, addr))

    async def handle_message(self, data: bytes, addr: tuple[str, int]):
        try:
            message = json.loads(data.decode("utf-8"))
            payload = message.get("payload")
            signature = message.get("signature")
            
            if not payload or not signature:
                return
            
            # Verify signature to protect against malicious network injection
            if not _verify_signature(payload, signature):
                logger.warning(f"Received untrusted or unsigned peer message from {addr[0]}")
                return
            
            # Verify timestamp to prevent replay attacks (30s window)
            current_time = time.time()
            if abs(current_time - payload.get("timestamp", 0)) > 30:
                logger.warning(f"Replay attempt or out-of-sync clock message from {addr[0]}")
                return
            
            # Prevent processing our own messages
            if payload.get("sender_id") == INSTANCE_ID:
                return

            msg_type = payload.get("type")
            if msg_type == "PING":
                await self.handle_ping(payload, addr)
            elif msg_type == "SYNC_REQ":
                await self.handle_sync_req(payload, addr)
            elif msg_type == "SYNC_RESP":
                await self.handle_sync_resp(payload, addr)

        except Exception as e:
            logger.debug(f"Error parsing incoming peer message: {e}")

    async def handle_ping(self, payload: Dict[str, Any], addr: tuple[str, int]):
        peer_has_changed = payload.get("admin_password_changed", False)
        our_has_changed = await check_is_admin_password_changed()
        
        # If the peer has changed password but we haven't, request sync
        if peer_has_changed and not our_has_changed:
            logger.info(f"Found peer {addr[0]} with changed admin credentials. Requesting sync...")
            await self.send_sync_req(addr)

    async def handle_sync_req(self, payload: Dict[str, Any], addr: tuple[str, int]):
        # Peer is requesting admin credentials. Only send if we have a changed password
        our_has_changed = await check_is_admin_password_changed()
        if our_has_changed:
            hashed_pw = await get_admin_hashed_password()
            if hashed_pw:
                await self.send_sync_resp(hashed_pw, addr)

    async def handle_sync_resp(self, payload: Dict[str, Any], addr: tuple[str, int]):
        # Received credentials response. Only update if we still need a password change
        our_has_changed = await check_is_admin_password_changed()
        if not our_has_changed:
            hashed_pw = payload.get("hashed_password")
            if hashed_pw:
                await update_admin_password(hashed_pw)

    def send_signed_message(self, payload: Dict[str, Any], addr: tuple[str, int] | str):
        if not self.transport:
            return
        
        signature = _sign_payload(payload)
        message = {"payload": payload, "signature": signature}
        data = json.dumps(message).encode("utf-8")
        
        if isinstance(addr, str):
            self.transport.sendto(data, (addr, UDP_PORT))
        else:
            self.transport.sendto(data, addr)

    async def send_ping(self):
        password_changed = await check_is_admin_password_changed()
        payload = {
            "type": "PING",
            "sender_id": INSTANCE_ID,
            "timestamp": time.time(),
            "admin_password_changed": password_changed
        }
        # Broadcast to local subnet
        self.send_signed_message(payload, "255.255.255.255")

    async def send_sync_req(self, addr: tuple[str, int]):
        payload = {
            "type": "SYNC_REQ",
            "sender_id": INSTANCE_ID,
            "timestamp": time.time()
        }
        self.send_signed_message(payload, addr)

    async def send_sync_resp(self, hashed_password: str, addr: tuple[str, int]):
        payload = {
            "type": "SYNC_RESP",
            "sender_id": INSTANCE_ID,
            "timestamp": time.time(),
            "hashed_password": hashed_password
        }
        self.send_signed_message(payload, addr)

async def start_peer_discovery() -> None:
    """Start peer discovery background listener and broadcaster loop."""
    loop = asyncio.get_running_loop()
    
    # Create socket for UDP broadcast
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    
    # On Linux/macOS, REUSEPORT allows multiple processes to bind to the same port
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        
    try:
        sock.bind(("0.0.0.0", UDP_PORT))
    except Exception as e:
        logger.error(f"Failed to bind peer discovery socket: {e}")
        sock.close()
        return

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: PeerDiscoveryProtocol(),
        sock=sock
    )

    try:
        while True:
            # Periodically broadcast PING
            await protocol.send_ping()
            await asyncio.sleep(10)
    except asyncio.CancelledError:
        logger.info("Peer discovery task stopped.")
    finally:
        transport.close()
