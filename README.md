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

Le premier run remplit le cache et envoie l’état au démarrage. Les suivants notifient uniquement en cas de **diff** (nouveaux / partis). Discord + ntfy peuvent être utilisés ensemble ; il suffit qu’un envoi réussisse.

## Fichiers

- `Dockerfile` — image Alpine + nmap + Python 3
- `scan_and_notify.py` — scan nmap, diff, Discord + ntfy (stdlib uniquement)
- `docker-compose.yml` — service + volume `scanner-data` pour l’état
