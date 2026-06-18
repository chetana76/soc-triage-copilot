"""
Mocked containment actions. In production these would call an EDR (CrowdStrike,
SentinelOne) or a firewall API. Here they just record the intent, which is all
the demo needs - and lets us trigger them safely on command.
"""

from datetime import datetime, timezone


def isolate_host(host: str) -> dict:
    return {
        "action": "isolate_host",
        "target": host,
        "status": "SIMULATED_OK",
        "ts": datetime.now(timezone.utc).isoformat(),
    }


def block_ip(ip: str) -> dict:
    return {
        "action": "block_ip",
        "target": ip,
        "status": "SIMULATED_OK",
        "ts": datetime.now(timezone.utc).isoformat(),
    }
