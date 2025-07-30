# SpyHunter v2.1 – Full Installation & Usage Guide

### Table of Contents

1. [Host prerequisites](#host-prerequisites)
2. [One‑time installation](#one-time-installation)
3. [Directory layout](#directory-layout)
4. [Daily workflow](#daily-workflow)
5. [Generated artefacts](#generated-artefacts)
6. [Troubleshooting](#troubleshooting)

---

### 1 · Host prerequisites

| Category  | Requirement                                             | Why                                                           |
| --------- | ------------------------------------------------------- | ------------------------------------------------------------- |
| OS        | **Ubuntu 22.04 LTS** (server or desktop)                | Script hard‑codes paths and APT names.                        |
| Privilege | **root (sudo)**                                         | Needs to install packages, enable monitor‑mode, kill drivers. |
| Storage   | ≥ 5 GB free on `/` (500 MB minimum sanity guard)        | Captures + PDFs.                                              |
| Hardware  | • HackRF One<br>• RTL‑SDR (RTL2832U)<br>• Ubertooth One | At least one of each detected by `lsusb`.                     |

> **Tip:** Plug devices in **before** first run and ensure Ubuntu sees them ( `lsusb` ).

---

### 2 · One‑time installation

```bash
# 1) create root directory
sudo mkdir /SpyHunter && sudo chown $USER:$USER /SpyHunter

# 2) drop files
#    – spyhunter.py         (the full 2.1 script)
#    – requirements.txt     (copy the block above)
#    – optional README.md   (this guide)
nano /SpyHunter/spyhunter.py      # paste the script
nano /SpyHunter/requirements.txt  # paste requirements

# 3) first run (auto‑installs everything)
sudo python3 /SpyHunter/spyhunter.py baseline_cmd
```

What happens on first run?

1. **APT phase** – installs SDR drivers, WeasyPrint libs, etc.
2. **Virtual‑env** in `/SpyHunter/.venv` + `requirements.txt` pip‑installed.
3. **Filesystem** – helper scripts, configs, templates are generated.
4. **Baseline capture** – a short RF/BLE/Wi‑Fi scan populates `/SpyHunter/baselines`.

Everything is idempotent; re‑running just skips installed parts.

---

### 3 · Directory layout

```
/SpyHunter
 ├─ spyhunter.py            # main launcher
 ├─ requirements.txt
 ├─ .venv/                  # isolated python
 ├─ bin/                    # helper bash wrappers (auto‑generated)
 ├─ config/
 │   ├─ settings.json       # tweak thresholds etc.
 │   └─ signatures.json     # benign / suspicious fingerprints
 ├─ data/
 │   ├─ captures/           # raw CSV/PCAP from each run
 │   ├─ baselines/          # processed baselines (*.json)
 │   ├─ reports/            # PDF outputs
 │   ├─ logs/
 │   │   ├─ system_audit.log
 │   │   └─ detection_alerts.log
 │   └─ ledger.db           # immutable SHA ledger
 └─ templates/
     └─ report_template.html
```

---

### 4 · Daily workflow

| Action                                        | Command                                                                            | What it does                                          |
| --------------------------------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------- |
| **Initial baseline**                          | `sudo python3 /SpyHunter/spyhunter.py baseline_cmd`                                | Records RF/BLE/Wi‑Fi footprint for future comparison. |
| **Quick sweep**                               | `sudo python3 /SpyHunter/spyhunter.py sweep_cmd --duration 180 --profile Office_1` | Uses latest baseline; produces PDF in `reports/`.     |
| **Full wizard** (create new baseline + sweep) | `sudo python3 /SpyHunter/spyhunter.py wizard --profile HQ_Floor1_Adv`              | End‑to‑end 5‑min scan; best for new locations.        |
| **Show last 10 reports**                      | `sudo python3 /SpyHunter/spyhunter.py ledger --rows 10`                            | Lists file names + SHA snippets.                      |

**Typical SOP**

1. Arrive on‑site → run **wizard** (new baseline + sweep).
2. Any change in layout/equipment → run **baseline\_cmd** again.
3. For routine checks (daily/weekly) → run **sweep\_cmd**.

---

### 5 · Generated artefacts

| File                                     | Location     | Purpose                                                          |
| ---------------------------------------- | ------------ | ---------------------------------------------------------------- |
| `baseline_*.json`                        | `baselines/` | Numerical RF powers, BLE & Wi‑Fi device lists.                   |
| `*_wifi*.csv / *_ble*.pcap / *_rtl*.csv` | `captures/`  | Raw evidence (kept until manual purge / retention days).         |
| `*_report.pdf`                           | `reports/`   | Human‑readable report incl. anomaly list & log tails.            |
| `ledger.db`                              | `data/`      | SQLite ledger – path + SHA‑512 of every report (tamper‑evident). |

---

### 6 · Troubleshooting

| Symptom                  | Likely cause / fix                                                                       |                |
| ------------------------ | ---------------------------------------------------------------------------------------- | -------------- |
| `No HackRF boards found` | USB cable / power / kernel driver conflict – run \`dmesg                                 | grep hackrf\`. |
| `rtl_test -t` fails      | DVB‑T kernel modules loaded. Script auto‑blacklists, but a **reboot** may be required.   |                |
| PDF empty or HTML shown  | WeasyPrint missing GTK/Pango libs – ensure `apt install weasyprint libpango1.0-0`.       |                |
| BLE capture 0 kB         | Ubertooth firmware < v2023‑07‑xx – upgrade with `ubertooth-dfu`.                         |                |
| Disk fills with captures | Change `settings.json → data_retention_days` or cron‑purge `captures/`.                  |                |
| Need extra SDR ranges    | Edit `settings.json` → `rf_scan.rtl_freqs_sweep_mhz` (comma‑separated start\:end\:step). |                |

---

**That’s it — happy hunting.** Feel free to tweak thresholds, report template, or helper scripts; all are regenerated only if missing, so manual edits persist.
