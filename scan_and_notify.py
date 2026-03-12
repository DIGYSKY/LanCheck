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
SCAN_INTERFACE = os.environ.get("SCAN_INTERFACE", "").strip()
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "").strip()


def _log_err(msg: str) -> None:
    """Écrit sur stderr avec flush pour que Docker affiche tout de suite."""
    print(msg, file=sys.stderr, flush=True)


def run_arp_scan(subnet: str, interface: str | None) -> list[dict[str, str]]:
    """Lance arp-scan (ARP uniquement) : ne retourne que les appareils répondant + MAC."""
    cmd = ["arp-scan", "--retry=2", "-q", subnet]
    if interface:
        cmd = ["arp-scan", "-I", interface, "--retry=2", "-q", subnet]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return []
    if result.returncode != 0:
        _log_err(f"[scan] arp-scan exit {result.returncode}, stderr: {result.stderr[:200] if result.stderr else '—'}")
        return []
    return parse_arpscan_output(result.stdout)


def parse_arpscan_output(text: str) -> list[dict[str, str]]:
    """Parse la sortie arp-scan : IP, MAC, (optionnel) Vendor (tab ou espaces)."""
    hosts: list[dict[str, str]] = []
    for line in text.strip().splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and ":" in parts[1]:
            ip, mac = parts[0], parts[1]
            if ip and not ip.startswith("#"):
                hosts.append({"ip": ip, "mac": mac})
    return hosts


def run_nmap_scan(subnet: str, interface: str | None) -> list[dict[str, str]]:
    """Fallback nmap -sn -PR (ARP)."""
    cmd = ["nmap", "-sn", "-PR", "-oX", "-", subnet]
    if interface:
        cmd = ["nmap", "-sn", "-PR", "-e", interface, "-oX", "-", subnet]
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


def _find_child(node: ET.Element, tag_suffix: str) -> ET.Element | None:
    """Trouve un enfant par nom de balise (gère le namespace nmap)."""
    for child in node:
        if child.tag.endswith(tag_suffix) or child.tag == tag_suffix:
            return child
    return None


def parse_nmap_xml(xml_str: str) -> list[dict[str, str]]:
    """Parse la sortie XML de nmap et extrait (ip, mac) par host. Uniquement les hôtes « up »."""
    hosts: list[dict[str, str]] = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError:
        return hosts
    for host in root.findall(".//host"):
        status = _find_child(host, "status")
        if status is not None and status.get("state") != "up":
            continue
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
    # Si trop d’entrées sans aucune MAC → scan en mode ping, pas ARP : ignorer (évite 256 faux positifs)
    if len(hosts) > 100 and not any(h.get("mac") and h["mac"] != "—" for h in hosts):
        _log_err("[scan] Trop d’hôtes sans MAC (scan non-ARP?) — résultat ignoré. Vérifier cap NET_RAW et réseau.")
        return []
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


def _post_webhook(webhook_url: str, content: str) -> bool:
    """Envoie un message texte au webhook Discord. Log l'erreur en cas d'échec."""
    if len(content) > 2000:
        content = content[:1997] + "..."
    body = json.dumps({"content": content}).encode("utf-8")
    req = request.Request(
        webhook_url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "DiscordBot (https://discord.com, 1.0)",
        },
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


def _post_ntfy(topic: str, content: str) -> bool:
    """Envoie un message à ntfy.sh (contourne Cloudflare, utile derrière VPN)."""
    url = f"https://ntfy.sh/{topic}"
    body = content[:4096].encode("utf-8")
    req = request.Request(
        url,
        data=body,
        headers={"Content-Type": "text/plain; charset=utf-8", "X-Title": "LAN Check"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as resp:
            if 200 <= resp.status < 300:
                return True
            _log_err(f"[ntfy] HTTP {resp.status}")
            return False
    except HTTPError as e:
        _log_err(f"[ntfy] HTTP {e.code}")
        return False
    except (URLError, OSError, Exception) as e:
        _log_err(f"[ntfy] Error: {e}")
        return False


def _send_notifications(content: str) -> bool:
    """Envoie le message à Discord et/ou ntfy. Retourne True si au moins un envoi a réussi."""
    ok = False
    if DISCORD_WEBHOOK_URL:
        if _post_webhook(DISCORD_WEBHOOK_URL, content):
            ok = True
    if NTFY_TOPIC:
        if _post_ntfy(NTFY_TOPIC, content):
            ok = True
    return ok


def _content_startup(current: list[dict[str, str]]) -> str:
    lines = "\n".join(format_device(d) for d in current)
    return f"**État au démarrage** ({len(current)} appareil(s))\n{lines}"


def _content_diff(new: list, gone: list) -> str:
    parts = []
    if new:
        lines = "\n".join(format_device(d) for d in new)
        parts.append(f"**Nouveaux sur le LAN**\n{lines}")
    if gone:
        lines = "\n".join(format_device(d) for d in gone)
        parts.append(f"**Partis du LAN**\n{lines}")
    return "\n\n".join(parts)


def main() -> int:
    previous = load_state(STATE_PATH)
    iface = SCAN_INTERFACE or None
    current = run_arp_scan(SUBNET, iface)
    if not current:
        current = run_nmap_scan(SUBNET, iface)
    if not current and previous:
        # Scan vide : on ne met pas à jour l'état pour éviter des faux "partis"
        return 0
    save_state(STATE_PATH, current)
    if not DISCORD_WEBHOOK_URL and not NTFY_TOPIC:
        return 0
    # Au démarrage (pas d'état précédent) : envoyer l'état actuel
    if not previous:
        if current and not _send_notifications(_content_startup(current)):
            _log_err("Notification failed (see [Discord]/[ntfy] lines above)")
            return 1
        return 0
    # Sinon : notifier seulement en cas de diff
    new, gone = diff(current, previous)
    if (new or gone) and not _send_notifications(_content_diff(new, gone)):
        _log_err("Notification failed (see [Discord]/[ntfy] lines above)")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
