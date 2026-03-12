# net-scanner

Conteneur Docker qui scanne le LAN à intervalle régulier, détecte les appareils **nouveaux** ou **partis**, et envoie un résumé par **Discord** et/ou **ntfy** (push).

## Prérequis

- Docker + Docker Compose
- Sous Linux : le conteneur utilise `network_mode: host` pour scanner le vrai LAN. Sur macOS/Windows (Docker Desktop), le « host » est la VM Docker, pas ta machine — pour scanner ton LAN depuis un Mac, exécute le stack sur une machine Linux (NAS, Pi, serveur) sur le même réseau.

## Configuration

1. Copie les variables d’environnement :
   ```bash
   cp .env.example .env
   ```
2. Édite `.env` : **Discord** (`DISCORD_WEBHOOK_URL`) et/ou **ntfy** (`NTFY_TOPIC`, ex. `lan-check-skynas`). Si Discord renvoie 403/1010 (VPN/datacenter), utilise ntfy : abonne-toi au topic sur [ntfy.sh](https://ntfy.sh).
3. Ajuste `SCAN_SUBNET` et `INTERVAL` si besoin.

## Lancement

```bash
docker compose up -d
```

Le premier run remplit le cache et envoie l’état au démarrage. Les suivants notifient uniquement en cas de **diff** (nouveaux / partis). Chaque appareil est affiché avec **IP — MAC — nom** (nom résolu par reverse DNS / mDNS si disponible). Discord + ntfy peuvent être utilisés ensemble ; il suffit qu’un envoi réussisse.

## Fichiers

- `Dockerfile` — image Alpine + nmap + Python 3
- `scan_and_notify.py` — scan nmap, diff, Discord + ntfy (stdlib uniquement)
- `watch_containers.py` — surveillance des conteneurs Docker + notifications
- `docker-compose.yml` — services (scanner LAN + watcher Docker)

## Service de surveillance Docker

Un second service, `docker-watcher`, envoie :

- **au démarrage** : l’état complet de tous les conteneurs Docker
- **à chaque changement de statut** (start/stop/restart, etc.) : une notification avec les conteneurs impactés + l’état complet actuel

Configuration supplémentaire dans `.env` :

- `DOCKER_WEBHOOK_URL` — second webhook Discord dédié au statut Docker
- `DOCKER_POLL_INTERVAL` — intervalle de polling de l’API Docker (en secondes, défaut 10)
- `DOCKER_SOCKET_PATH` — chemin du socket Docker (défaut `/var/run/docker.sock`)

Le service monte automatiquement `/var/run/docker.sock` en lecture seule pour interroger l’API Docker du host.
