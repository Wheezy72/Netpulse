from fastapi import APIRouter

from app.api.routes import (
    auth,
    backup,
    captures,
    chatbot,
    device_actions,
    devices,
    google_auth,
    health,
    insights,
    logs,
    metrics,
    network_segments,
    nmap,
    packets,
    pcaps,
    playbooks,
    plugins,
    recon,
    reports,
    routers,
    scripts,
    settings,
    snmp,
    syslog_receiver,
    threat_intel,
    uptime,
    ws,
)
from app.plugins import load_builtin_plugins

api_router = APIRouter()
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(google_auth.router, prefix="/auth/google", tags=["auth"])
api_router.include_router(scripts.router, prefix="/scripts", tags=["scripts"])
api_router.include_router(recon.router, prefix="/recon", tags=["recon"])
api_router.include_router(devices.router, prefix="/devices", tags=["devices"])
api_router.include_router(routers.router, prefix="/routers", tags=["routers"])
api_router.include_router(metrics.router, prefix="/metrics", tags=["metrics"])
api_router.include_router(captures.router, prefix="/captures", tags=["captures"])
api_router.include_router(pcaps.router, prefix="/pcaps", tags=["pcaps"])
api_router.include_router(packets.router, prefix="/packets", tags=["packets"])
api_router.include_router(network_segments.router, prefix="/network-segments", tags=["network-segments"])
api_router.include_router(settings.router, prefix="/settings", tags=["settings"])
api_router.include_router(playbooks.router, prefix="/playbooks", tags=["playbooks"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(chatbot.router, prefix="/chatbot", tags=["chatbot"])
api_router.include_router(insights.router, prefix="/insights", tags=["insights"])
api_router.include_router(threat_intel.router, prefix="/threat-intel", tags=["threat-intel"])
api_router.include_router(logs.router, prefix="/logs", tags=["logs"])
api_router.include_router(ws.router, prefix="/ws", tags=["ws"])
api_router.include_router(nmap.router, prefix="/nmap", tags=["nmap"])
api_router.include_router(uptime.router)
api_router.include_router(snmp.router, prefix="/snmp", tags=["snmp"])
api_router.include_router(syslog_receiver.router, prefix="/syslog", tags=["syslog"])
api_router.include_router(device_actions.router, prefix="/device-actions", tags=["device-actions"])
api_router.include_router(backup.router, prefix="/backup", tags=["backup"])
api_router.include_router(plugins.router, prefix="/plugins", tags=["plugins"])

load_builtin_plugins()