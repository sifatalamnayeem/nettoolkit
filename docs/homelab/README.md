# Home lab: Pi-hole + WireGuard with Docker

A small, reproducible home network setup that you can bring up with one command
and describe in an interview:

- **Pi-hole** blocks ads and trackers for every device on your network by acting
  as the DNS server, and shows you which devices ask for which domains.
- **WireGuard** lets your phone and laptop reach your home network securely from
  anywhere, and use Pi-hole's ad blocking while away.
- **NetToolkit** (this repo) watches the setup: the uptime monitor checks that
  DNS and the VPN port respond and sends a Telegram alert when they stop.

```
                    Internet
                       |
                  [ Router ]  --- forwards only UDP 51820 --->  WireGuard (VPN)
                       |
        LAN 192.168.1.0/24
        |          |            |
     laptop     phone     [ Home server  HOST_IP ]
                            ├─ Pi-hole    DNS :53, web :8080
                            ├─ WireGuard  UDP :51820
                            └─ nettool monitor / dashboard
```

> Written from the official [Pi-hole Docker docs](https://docs.pi-hole.net/docker/)
> and the [LinuxServer WireGuard image docs](https://docs.linuxserver.io/images/docker-wireguard).
> The compose file passes `docker compose config` (syntax and variables), but I
> could not start the containers where this was written, so it has **not been
> tested end to end**. Image options change between releases: if something
> differs, trust those pages over this file, and note what you fixed in your repo.

## Requirements

- A Linux machine that stays on (a Raspberry Pi, an old laptop or a small VM).
- Docker with the Compose plugin (`docker compose version` should work).
- A router where you can set a DHCP reservation and forward one UDP port.
- For access from outside: a public IP address or a dynamic DNS name. Some ISPs
  (CGNAT) do not give a reachable public IP; in that case WireGuard cannot accept
  connections from outside without a relay. Check this first.

## Setup

1. **Give the server a fixed LAN address** (DHCP reservation on the router), for example `192.168.1.10`.
2. **Configure:**
   ```bash
   cd docs/homelab
   cp .env.example .env
   nano .env            # HOST_IP, PIHOLE_PASSWORD, WG_SERVERURL, WG_PEERS
   chmod 600 .env
   ```
3. **Free port 53 if needed.** On Ubuntu, `systemd-resolved` already listens on
   port 53 and Pi-hole will fail to start. Check with `sudo ss -lntup | grep ':53 '`.
   If it is in use, set `DNSStubListener=no` in `/etc/systemd/resolved.conf` and
   run `sudo systemctl restart systemd-resolved`.
4. **Start:**
   ```bash
   docker compose up -d
   docker compose ps
   docker compose logs -f pihole      # Ctrl+C to leave
   ```
5. **Check Pi-hole:** open `http://HOST_IP:8080/admin` and sign in with your password.
   From another computer: `nslookup example.com HOST_IP` should return an answer.
6. **Point your network at it.** Easiest: in the router's DHCP settings, set the
   DNS server to `HOST_IP`. (Keep a way back: if the server is off, nobody has DNS.
   Many people add a secondary DNS only after understanding that it bypasses
   blocking.) Reconnect a device and confirm it works.
7. **WireGuard clients.** Peer configs are created under `wireguard-config/peer_<name>/`.
   Show a QR code to scan with the WireGuard phone app:
   ```bash
   docker exec -it wireguard /app/show-peer phone
   ```
   `LOG_CONFS` is off on purpose: the QR code contains the peer's private key, and
   you do not want it sitting in the container logs.
8. **Forward one port on the router:** UDP `51820` to `HOST_IP`. Nothing else.
9. **Test the VPN** from mobile data (not your home Wi-Fi): connect, then browse
   and open the Pi-hole page. Your public IP should now be your home IP.

## Monitor it with NetToolkit

```json
{
  "interval": 60,
  "targets": [
    { "name": "Pi-hole DNS",  "type": "tcp",  "host": "192.168.1.10", "port": 53 },
    { "name": "Pi-hole web",  "type": "http", "url": "http://192.168.1.10:8080/admin/login", "expect_status": 200 },
    { "name": "Router",       "type": "tcp",  "host": "192.168.1.1",  "port": 80 }
  ]
}
```

```bash
nettool monitor run -c monitor.json
nettool dashboard
```

The WireGuard port is UDP, which a TCP check cannot test. Test it from outside by
actually connecting with a peer.

## Security checklist

- [ ] Only UDP 51820 is forwarded on the router. **Never forward 53 or 8080.** An
      open DNS resolver is abused for attacks and the Pi-hole admin page is not
      meant to face the internet. (Compose binds both to `HOST_IP` as a second line
      of defence.)
- [ ] `.env` is `chmod 600` and is **not committed** (the repo's `.gitignore` covers it).
- [ ] `wireguard-config/` holds private keys: not committed, and backed up somewhere safe.
- [ ] A long, unique Pi-hole password.
- [ ] Router admin password changed from the default; remote administration of the router is off.
- [ ] Server updated regularly: `sudo apt update && sudo apt upgrade`, then
      `docker compose pull && docker compose up -d`.
- [ ] One WireGuard peer per device. If a phone is lost, delete that peer folder and restart
      the container so its key stops working.
- [ ] SSH to the server uses keys, password login disabled. Run
      `sudo nettool logscan /var/log/auth.log` weekly to see who is knocking.
- [ ] `latest` tags move. For stability, pin versions (`pihole/pihole:2025.xx.x`) once it works.

## Backup and restore

```bash
docker compose down
tar czf homelab-backup-$(date +%F).tar.gz .env etc-pihole wireguard-config
chmod 600 homelab-backup-*.tar.gz        # contains secrets; store it off the server
docker compose up -d
```

To restore, extract the archive into `docs/homelab/` on the new machine and run
`docker compose up -d`. Peers keep working because their keys are in `wireguard-config/`.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| Pi-hole container exits, "address already in use" | Something else uses port 53 (see step 3) |
| `nslookup` times out from another PC | `HOST_IP` in `.env` is not the server's real LAN IP, or a firewall (`ufw`) blocks 53 |
| Pages load slowly after setting the router DNS | Pi-hole upstream DNS in its settings is unreachable |
| VPN connects but nothing loads | Client `AllowedIPs` and DNS; try `ALLOWEDIPS=0.0.0.0/0`; IPv6 errors are a known cause (see the LinuxServer docs) |
| VPN never connects from outside | Router forwards UDP 51820 to the right IP? Public IP or CGNAT? `SERVERURL` correct? |
| WireGuard container restarts | WireGuard kernel module missing on the host; the image docs describe `SYS_MODULE` and `/lib/modules` |

## What to show in your portfolio

A screenshot of the Pi-hole dashboard (hide your IPs), the NetToolkit dashboard
watching these services, and a short note about what you changed and why. Describing
a problem you hit (for example the port 53 conflict) and how you fixed it is worth
more than a perfect setup.
