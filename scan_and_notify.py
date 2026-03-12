#!/usr/bin/env python3
"""
Scan LAN (nmap), compare avec l'état précédent, notifier Discord en cas de changement.
Utilise uniquement la stdlib (pas de deps pip).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib import request
from urllib.error import HTTPError, URLError

STATE_PATH = Path("/data/state.json")
SUBNET = os.environ.get("SCAN_SUBNET", "192.168.1.0/24")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()


def run_nmap_scan(subnet: str) -> list[dict[str, str]]:
    """Lance nmap -sn (ARP) et retourne une liste de {ip, mac}."""
    cmd = ["nmap", "-sn", "-oX", "-", subnet]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return []
    if result.returncode != 0:
        return []
    return parse_nmap_xml(result.stdout)


def parse_nmap_xml(xml_str: str) -> list[dict[str, str]]:
    """Parse la sortie XML de nmap et extrait (ip, mac) par host."""
    hosts: list[dict[str, str]] = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return hosts
    for host in root.findall(".//host"):
        ip = ""
        mac = ""
        for addr in host.findall("address"):
            atype = addr.get("addrtype")
            addr_val = addr.get("addr", "")
            if atype == "ipv4":
                ip = addr_val
            elif atype == "mac":
                mac = addr_val
        if ip:
            hosts.append({"ip": ip, "mac": mac or "—"})
    return hosts


def load_state(path: Path) -> list[dict[str, str]]:
    """Charge l'état précédent depuis le fichier JSON."""
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_state(path: Path, state: list[dict[str, str]]) -> None:
    """Sauvegarde l'état dans le fichier JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def diff(
    current: list[dict[str, str]], previous: list[dict[str, str]]
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Retourne (nouveaux, partis) par rapport à l'état précédent (clé = ip)."""
    prev_by_ip = {h["ip"]: h for h in previous}
    curr_by_ip = {h["ip"]: h for h in current}
    new = [curr_by_ip[ip] for ip in curr_by_ip if ip not in prev_by_ip]
    gone = [prev_by_ip[ip] for ip in prev_by_ip if ip not in curr_by_ip]
    return new, gone


def format_device(d: dict[str, str]) -> str:
    return f"`{d['ip']}` — {d['mac']}"


def _log_err(msg: str) -> None:
    """Écrit sur stderr avec flush pour que Docker affiche tout de suite."""
    print(msg, file=sys.stderr, flush=True)


def _post_webhook(webhook_url: str, content: str) -> bool:
    """Envoie un message texte au webhook Discord. Log l'erreur en cas d'échec."""
    if len(content) > 2000:
        content = content[:1997] + "..."
    body = json.dumps({"content": content}).encode("utf-8")
    req = request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                return True
            msg = resp.read().decode("utf-8", errors="replace")[:500]
            _log_err(f"[Discord] HTTP {resp.status}: {msg}")
            return False
    except HTTPError as e:
        try:
            msg = (e.fp.read().decode("utf-8", errors="replace")[:500]) if e.fp else str(e)
        except Exception:
            msg = str(e)
        _log_err(f"[Discord] HTTP {e.code}: {msg}")
        return False
    except URLError as e:
        _log_err(f"[Discord] URL error: {e.reason}")
        return False
    except OSError as e:
        _log_err(f"[Discord] Error: {type(e).__name__}: {e}")
        return False
    except Exception as e:
        _log_err(f"[Discord] Unexpected error: {type(e).__name__}: {e}")
        return False


def send_discord_startup(webhook_url: str, current: list[dict[str, str]]) -> bool:
    """Envoie l'état actuel au webhook (message « État au démarrage »)."""
    if not current:
        return True
    lines = "\n".join(format_device(d) for d in current)
    content = f"**État au démarrage** ({len(current)} appareil(s))\n{lines}"
    return _post_webhook(webhook_url, content)


def send_discord(webhook_url: str, new: list, gone: list) -> bool:
    """Envoie un message au webhook Discord avec le diff."""
    parts = []
    if new:
        lines = "\n".join(format_device(d) for d in new)
        parts.append(f"**Nouveaux sur le LAN**\n{lines}")
    if gone:
        lines = "\n".join(format_device(d) for d in gone)
        parts.append(f"**Partis du LAN**\n{lines}")
    if not parts:
        return True
    content = "\n\n".join(parts)
    return _post_webhook(webhook_url, content)


def main() -> int:
    previous = load_state(STATE_PATH)
    current = run_nmap_scan(SUBNET)
    if not current and previous:
        # Scan vide : on ne met pas à jour l'état pour éviter des faux "partis"
        return 0
    save_state(STATE_PATH, current)
    if not DISCORD_WEBHOOK_URL:
        return 0
    # Au démarrage (pas d'état précédent) : envoyer l'état actuel
    if not previous:
        if current and not send_discord_startup(DISCORD_WEBHOOK_URL, current):
            _log_err("Discord webhook failed (see [Discord] line above for details)")
            return 1
        return 0
    # Sinon : notifier seulement en cas de diff
    new, gone = diff(current, previous)
    if (new or gone) and not send_discord(DISCORD_WEBHOOK_URL, new, gone):
        _log_err("Discord webhook failed (see [Discord] line above for details)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
