# net-scanner

Conteneur Docker qui scanne le LAN à intervalle régulier, détecte les appareils **nouveaux** ou **partis**, et envoie un résumé sur un webhook Discord.

## Prérequis

- Docker + Docker Compose
- Sous Linux : le conteneur utilise `network_mode: host` pour scanner le vrai LAN. Sur macOS/Windows (Docker Desktop), le « host » est la VM Docker, pas ta machine — pour scanner ton LAN depuis un Mac, exécute le stack sur une machine Linux (NAS, Pi, serveur) sur le même réseau.

## Configuration

1. Copie les variables d’environnement :
   ```bash
   cp .env.example .env
   ```
2. Édite `.env` et renseigne au minimum `DISCORD_WEBHOOK_URL` (crée un webhook dans Discord : serveur → Paramètres → Intégrations → Webhooks).
3. Ajuste `SCAN_SUBNET` et `INTERVAL` si besoin.

## Lancement

```bash
docker compose up -d
```

Le premier run remplit le cache (`/data/state.json`). Les runs suivants comparent avec ce cache et envoient un message Discord uniquement en cas de **diff** (nouveaux / partis).

## Fichiers

- `Dockerfile` — image Alpine + nmap + Python 3
- `scan_and_notify.py` — scan nmap, diff, envoi Discord (stdlib uniquement)
- `docker-compose.yml` — service + volume `scanner-data` pour l’état
