# NetToolkit

A modular networking toolkit written in Python, all behind a single `nettool`
command. No third-party dependencies (standard library only).

| Tool | What it does |
|------|--------------|
| `subnet` | Subnet calculator and splitter (IPv4/IPv6) |
| `discover` / `scan` | Ping sweep and TCP port scanner |
| `monitor` | Uptime monitor (HTTP, TCP, SSL expiry) with Telegram alerts |
| `speedlog` | Internet speed logger with history and CSV export |

> **Use responsibly:** only scan networks and hosts that you own or have
> explicit permission to test.

## Install

```bash
git clone https://github.com/sifatalamnayeem/nettoolkit.git
cd nettoolkit
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Usage

```bash
# Subnet calculator
nettool subnet 192.168.1.10/24
nettool subnet 192.168.1.0/24 --split 26
nettool subnet 10.0.0.0/8 --json

# Find live hosts on your LAN
nettool discover 192.168.0.0/24

# Scan ports on a host you own
nettool scan 127.0.0.1                 # common ports
nettool scan 192.168.0.1 -p 1-1024
nettool scan localhost -p 22,80,443 --all --json
```

### Uptime monitor + Telegram alerts

```bash
cp monitor.example.json monitor.json        # edit your targets
export TELEGRAM_BOT_TOKEN="123456:ABC..."   # see .env.example for setup
export TELEGRAM_CHAT_ID="123456789"

nettool alert-test                          # check that Telegram works
nettool monitor run -c monitor.json         # runs forever, Ctrl+C to stop
nettool monitor run -c monitor.json --once  # one round, exit code 1 if anything is down
nettool monitor status --hours 24           # uptime % from stored history
```

Alerts are sent only when a target changes state: it is declared **DOWN** after
`fail_threshold` consecutive failures (default 2) and you get one **RECOVERED**
message when it comes back. Without Telegram variables, alerts print to the console.

Target types in `monitor.json`:

```json
{ "type": "http", "url": "https://example.com", "expect_status": 200 }
{ "type": "tcp",  "host": "example.com", "port": 22 }
{ "type": "ssl",  "host": "example.com", "warn_days": 14 }
```

### Speed logger

```bash
nettool speedlog run                # one test (ping, download, upload) saved to the database
nettool speedlog loop --every 3600  # test every hour
nettool speedlog history -n 20
nettool speedlog export speed.csv
```

Results are stored in SQLite at `~/.nettoolkit/data.db` (override with `NETTOOL_DB`
or `--db`). The speed test uses Cloudflare's public test endpoints by default.

Example output:

```
$ nettool subnet 192.168.1.10/24
Network         192.168.1.0/24
Netmask         255.255.255.0
Wildcard        0.0.0.255
Broadcast       192.168.1.255
First host      192.168.1.1
Last host       192.168.1.254
Total addresses 256
Usable hosts    254
Private         yes
```

> Add your own screenshot here once you run it on your network.

## Project structure

```
nettoolkit/
├── nettoolkit/
│   ├── subnet/      # subnet calculator
│   ├── scanner/     # host discovery + port scanner
│   ├── monitor/     # uptime checks + state-change alerting
│   ├── alerts/      # Telegram / console notifiers
│   ├── speedlog/    # speed test
│   ├── storage.py   # SQLite history (used by the Phase 3 dashboard)
│   └── cli.py       # `nettool` command
├── tests/
└── pyproject.toml
```

## Run the tests

```bash
pytest
```

## Roadmap

- [x] Phase 1: subnet calculator, scanner, CLI
- [x] Phase 2: uptime monitor + Telegram alerts, speed test logger
- [ ] Phase 3: web dashboard (Flask/Streamlit)
- [ ] Phase 4: packet sniffer, log analyzer, Netmiko automation, home lab docs

## License

MIT
