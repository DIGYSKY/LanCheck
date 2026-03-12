#!/usr/bin/env python3
"""
Surveille les conteneurs Docker via l'API de Docker et envoie
des notifications sur un second webhook :

- au démarrage : état complet des conteneurs
- ensuite : à chaque changement de statut, avec récap complet actuel

Stdlib uniquement (comme le scanner LAN).
"""

from __future__ import annotations

import http.client
import json
import os
import socket
import sys
import time
from pathlib import Path
from urllib import request
from urllib.error import HTTPError, URLError

STATE_PATH = Path("/data/docker_state.json")
DOCKER_SOCKET_PATH = os.environ.get("DOCKER_SOCKET_PATH", "/var/run/docker.sock")
DOCKER_WEBHOOK_URL = os.environ.get("DOCKER_WEBHOOK_URL", "").strip()
POLL_INTERVAL = int(os.environ.get("DOCKER_POLL_INTERVAL", "10") or "10")


def _log_err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


class UnixSocketHTTPConnection(http.client.HTTPConnection):
    """Connexion HTTP vers l'API Docker via socket Unix."""

    def __init__(self, path: str, timeout: float = 10.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.unix_socket_path = path

    def connect(self) -> None:  # type: ignore[override]
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self.unix_socket_path)
        except OSError:
            sock.close()
            raise
        self.sock = sock


def _docker_get(path: str) -> bytes:
    """GET simple sur l'API Docker (via /var/run/docker.sock)."""
    conn = UnixSocketHTTPConnection(DOCKER_SOCKET_PATH, timeout=10.0)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        data = resp.read()
        if resp.status != 200:
            raise RuntimeError(f"Docker API HTTP {resp.status}: {data[:200]!r}")
        return data
    finally:
        conn.close()


def list_containers() -> list[dict[str, str]]:
    """Retourne une liste simplifiée de conteneurs (id, nom, image, state, status)."""
    try:
        raw = _docker_get("/containers/json?all=1")
        decoded = json.loads(raw.decode("utf-8"))
    except Exception as e:
        _log_err(f"[docker-watcher] Impossible de récupérer la liste des conteneurs: {e}")
        return []

    result: list[dict[str, str]] = []
    for c in decoded:
        cid = c.get("Id") or ""
        names = c.get("Names") or []
        name = names[0].lstrip("/") if names else cid[:12]
        image = c.get("Image") or ""
        state = c.get("State") or ""
        status = c.get("Status") or ""
        result.append(
            {
                "id": cid,
                "name": name,
                "image": image,
                "state": state,
                "status": status,
            }
        )
    return result


def load_state(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_state(path: Path, state: list[dict[str, str]]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        tmp.replace(path)
    except OSError as e:
        _log_err(f"[docker-watcher] Impossible d'écrire l'état: {e}")


def diff_containers(
    current: list[dict[str, str]], previous: list[dict[str, str]]
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]]]:
    """
    Retourne (changed, new, gone) par rapport à l'état précédent.

    - changed : même id, mais state différent
    - new : id présent seulement dans current
    - gone : id présent seulement dans previous
    """
    prev_by_id = {c["id"]: c for c in previous}
    curr_by_id = {c["id"]: c for c in current}

    new = [curr_by_id[i] for i in curr_by_id if i not in prev_by_id]
    gone = [prev_by_id[i] for i in prev_by_id if i not in curr_by_id]

    changed: list[dict[str, str]] = []
    for cid, curr in curr_by_id.items():
        prev = prev_by_id.get(cid)
        if not prev:
            continue
        # On ne compare que "state" pour éviter les variations d'uptime
        # (ex: "Up 13 minutes" -> "Up 14 minutes") qui feraient des notifs inutiles.
        if curr.get("state") != prev.get("state"):
            changed.append(curr)

    return changed, new, gone


def format_container(c: dict[str, str]) -> str:
    name = c.get("name") or c.get("id", "")[:12]
    image = c.get("image") or "?"
    state = c.get("state") or "?"
    status = c.get("status") or ""
    if status:
        return f"`{name}` — {image} — {state} ({status})"
    return f"`{name}` — {image} — {state}"


def _post_webhook(webhook_url: str, content: str) -> bool:
    """Envoie un message texte au webhook Discord."""
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
            _log_err(f"[docker-watcher] Discord HTTP {resp.status}: {msg}")
            return False
    except HTTPError as e:
        try:
            msg = (e.fp.read().decode("utf-8", errors="replace")[:500]) if e.fp else str(e)
        except Exception:
            msg = str(e)
        _log_err(f"[docker-watcher] Discord HTTP {e.code}: {msg}")
        return False
    except URLError as e:
        _log_err(f"[docker-watcher] Discord URL error: {e.reason}")
        return False
    except OSError as e:
        _log_err(f"[docker-watcher] Discord error: {type(e).__name__}: {e}")
        return False
    except Exception as e:
        _log_err(f"[docker-watcher] Discord unexpected error: {type(e).__name__}: {e}")
        return False


def _content_startup(current: list[dict[str, str]]) -> str:
    lines = "\n".join(format_container(c) for c in current) or "_Aucun conteneur._"
    return f"**Docker – état au démarrage** ({len(current)} conteneur(s))\n{lines}"


def _content_diff(
    changed: list[dict[str, str]],
    new: list[dict[str, str]],
    gone: list[dict[str, str]],
    current: list[dict[str, str]],
) -> str:
    parts: list[str] = []
    if new:
        lines = "\n".join(format_container(c) for c in new)
        parts.append(f"**Docker – nouveaux conteneurs**\n{lines}")
    if gone:
        lines = "\n".join(format_container(c) for c in gone)
        parts.append(f"**Docker – conteneurs supprimés**\n{lines}")
    if changed:
        lines = "\n".join(format_container(c) for c in changed)
        parts.append(f"**Docker – statut modifié**\n{lines}")
    if current:
        lines = "\n".join(format_container(c) for c in current)
        parts.append(f"**Docker – état actuel** ({len(current)} conteneur(s))\n{lines}")
    return "\n\n".join(parts)


def main() -> int:
    if not DOCKER_WEBHOOK_URL:
        _log_err("[docker-watcher] DOCKER_WEBHOOK_URL non défini, arrêt.")
        return 0

    previous = load_state(STATE_PATH)
    _log_err(f"[docker-watcher] Démarrage, intervalle = {POLL_INTERVAL}s")

    while True:
        current = list_containers()
        _log_err(
            f"[docker-watcher] Scan: {len(current)} conteneur(s) trouvés, "
            f"précédent={len(previous)}"
        )
        if not current and not previous:
            # Rien à signaler, on attend simplement.
            time.sleep(POLL_INTERVAL)
            continue

        if not previous:
            # Premier état connu : envoi de l'état complet.
            _log_err("[docker-watcher] Envoi de l'état complet initial à Discord…")
            if _post_webhook(DOCKER_WEBHOOK_URL, _content_startup(current)):
                _log_err("[docker-watcher] Notification de démarrage envoyée avec succès.")
            else:
                _log_err("[docker-watcher] Échec de la notification de démarrage.")
            previous = current
            save_state(STATE_PATH, current)
            time.sleep(POLL_INTERVAL)
            continue

        changed, new, gone = diff_containers(current, previous)
        if changed or new or gone:
            _log_err(
                "[docker-watcher] Changement détecté : "
                f"changed={len(changed)}, new={len(new)}, gone={len(gone)}"
            )
            content = _content_diff(changed, new, gone, current)
            _log_err("[docker-watcher] Envoi de la notification de changement à Discord…")
            if _post_webhook(DOCKER_WEBHOOK_URL, content):
                _log_err("[docker-watcher] Notification de changement envoyée avec succès.")
                previous = current
                save_state(STATE_PATH, current)
            else:
                _log_err("[docker-watcher] Échec de la notification de changement.")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    sys.exit(main())

