# Image minimale pour scan LAN + notification Discord
FROM alpine:3.19

RUN apk add --no-cache \
    arp-scan \
    nmap \
    python3 \
    && rm -rf /var/cache/apk/*

WORKDIR /app
COPY scan_and_notify.py /app/
COPY watch_containers.py /app/

# nmap -sn nécessite des capacités réseau (ARP)
# On lance le script via le entrypoint du compose
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["while true; do python3 /app/scan_and_notify.py; sleep \"${INTERVAL:-300}\"; done"]
