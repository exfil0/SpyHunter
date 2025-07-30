# SpyHunter v2.1 — Veil‑Piercing Wizard

*Autonomous RF / BLE / Wi‑Fi counter‑surveillance toolkit*

![MIT License](https://img.shields.io/badge/license-MIT-blue)

> **Repo** · [https://github.com/exfil0/SpyHunter](https://github.com/exfil0/SpyHunter)

---

## Requirements (`requirements.txt`)

```text
# SpyHunter runtime Python deps
click>=8.1
colorama>=0.4
psutil>=5.9
PyYAML>=6.0

# Data analysis
numpy>=1.26
pandas>=2.2

# Packet & RF processing
scapy==2.4.5

# Reporting / templating
Jinja2>=3.1
fpdf>=1.7
weasyprint>=62.1
```

---

## Table of Contents

1. [Features](#features)
2. [Architecture & folder layout](#architecture--folder-layout)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Daily workflow](#daily-workflow)
6. [Generated artefacts](#generated-artefacts)
7. [Troubleshooting](#troubleshooting)

---

## Features

* **Tri‑band capture** – HackRF sweeps, RTL‑SDR slices, Ubertooth BLE pcaps, airodump Wi‑Fi csv/pcaps.
* **Advanced analytics** – RF power‑bin deltas, BLE service fingerprinting, hidden‑SSID & rogue‑AP detection.
* **Cross‑protocol groundwork** – timestamps preserved for future correlation engine.
* **Immutable ledger** – SHA‑512 of every PDF report stored in SQLite.
* **Single‑command wizard** – `sudo python3 spyhunter.py wizard` fully automates baseline → sweep → PDF.

---

## Architecture & folder layout

```text
/SpyHunter
 ├─ spyhunter.py            # main launcher
 ├─ requirements.txt        # Python deps
 ├─ bin/                    # helper bash wrappers (auto‑generated)
 ├─ config/                 # settings.json & signatures.json
 ├─ data/
 │   ├─ captures/           # raw CSV / PCAP / logs
 │   ├─ baselines/          # processed fingerprints
 │   ├─ reports/            # PDF outputs
 │   ├─ logs/
 │   │   ├─ system_audit.log
 │   │   └─ detection_alerts.log
 │   └─ ledger.db           # SHA ledger
 ├─ templates/
 │   └─ report_template.html
 └─ .venv/                  # isolated Python (auto‑created)
```

---

## Prerequisites

| Item      | Requirement                                   |
| --------- | --------------------------------------------- |
| OS        | Ubuntu 22.04 LTS                              |
| Privilege | root / sudo                                   |
| Storage   | ≥ 5 GB free (script aborts if < 500 MB)       |
| Hardware  | HackRF One, RTL‑SDR (RTL2832U), Ubertooth One |
| Internet  | Required on first run                         |

---

## Installation

```bash
# Clone repository
sudo git clone https://github.com/exfil0/SpyHunter.git /SpyHunter
cd /SpyHunter

# First launch (installs APT + pip deps, creates baseline)
sudo python3 spyhunter.py baseline_cmd
```

The first run is **idempotent** – subsequent runs skip installed parts.

---

## Daily workflow

| Purpose                       | Command                                                                  |
| ----------------------------- | ------------------------------------------------------------------------ |
| Create/refresh baseline       | `sudo python3 spyhunter.py baseline_cmd`                                 |
| One‑off sweep                 | `sudo python3 spyhunter.py sweep_cmd --duration 300 --profile Office_AM` |
| Full wizard (baseline+ sweep) | `sudo python3 spyhunter.py wizard --profile HQ_Floor1_Adv`               |
| View ledger                   | `sudo python3 spyhunter.py ledger --rows 10`                             |

---

## Generated artefacts

| Path              | Description                                   |
| ----------------- | --------------------------------------------- |
| `data/captures/`  | Raw evidence from each scan                   |
| `data/baselines/` | Environment fingerprints                      |
| `data/reports/`   | PDF reports with anomalies                    |
| `data/ledger.db`  | Immutable ledger (filename + SHA + timestamp) |

---

## Troubleshooting

| Symptom                | Fix                                                                       |
| ---------------------- | ------------------------------------------------------------------------- |
| No HackRF boards found | Check USB, `dmesg`; ensure `1d50:6089` present                            |
| `rtl_test -t` fails    | DVB‑T drivers loaded → script blacklists; reboot once                     |
| Empty BLE pcap         | Upgrade Ubertooth firmware (`ubertooth-dfu`)                              |
| Blank PDF              | Ensure `libpango1.0-0`, `libgdk-pixbuf2.0-0` installed (wizard does this) |
| Disk fills             | Purge `data/captures/` or adjust retention logic                          |

---

### Contributing

1. Fork the repo and create a feature branch.
2. Follow PEP‑8; run `black` + `isort` before opening a PR.

### License

MIT – see `LICENSE` in the repository.
