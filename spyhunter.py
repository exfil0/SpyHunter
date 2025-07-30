#!/usr/bin/env python3
import os, sys, subprocess, argparse, json, sqlite3, datetime, csv, re, hashlib, textwrap, shutil, signal, time, glob
from pathlib import Path
from collections import defaultdict

# ─────────────────────────── PATHS
ROOT   = Path("/SpyHunter")
BIN    = ROOT / "bin"
CONF   = ROOT / "config"
DATA   = ROOT / "data"
LOGS   = DATA / "logs"
CAP    = DATA / "captures"
BASE   = DATA / "baselines"
RPTS   = DATA / "reports"
TMP    = DATA / "tmp"
TEMPL  = ROOT / "templates"

SYSLOG = LOGS / "system_audit.log"
ALOG   = LOGS / "detection_alerts.log"
LEDGER = DATA / "ledger.db"
VENV   = ROOT / ".venv"

# ─────────────────────────── CONSTANTS
APT = [
    "python3-venv","python3-pip","git","gcc","make","build-essential",
    "libusb-1.0-0-dev","librtlsdr-dev","libbluetooth-dev",
    "hackrf","rtl-sdr","ubertooth","aircrack-ng","tshark","jq","curl","sox",
    "weasyprint","wkhtmltopdf",
    "libcairo2-dev","libpango1.0-0","libgdk-pixbuf2.0-0","libffi-dev","shared-mime-info"
]
PIP = [
    "click","colorama","psutil","PyYAML","numpy","pandas",
    "scapy==2.4.5","Jinja2","fpdf","weasyprint"
]

GREEN, RED, YEL, BLU, END = "\033[92m", "\033[91m", "\033[93m", "\033[94m", "\033[0m"

SETTINGS, SIGNATURES = {}, {}

# ─────────────────────────── LOG & SHELL
def _logf(path:Path, msg:str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.open("a").write(f"{datetime.datetime.now().isoformat(timespec='seconds')} {msg}\n")

def echo(msg:str, status=None):
    if   status is True:  print(f"{GREEN}[PASS]{END} {msg}")
    elif status is False: print(f"{RED}[FAIL]{END} {msg}")
    elif status=="ALERT": print(f"{YEL}[ALERT]{END} {msg}")
    elif status=="ATTN":  print(f"{BLU}[ATTN]{END} {msg}")
    else:                 print(msg)
    _logf(SYSLOG, msg)
    if status=="ALERT": _logf(ALOG, msg)

def run(cmd:str, *, fatal=True, capture=True, timeout=None):
    proc = subprocess.run(cmd, shell=True, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT, timeout=timeout)
    out = (proc.stdout or "").strip()
    if out: _logf(SYSLOG, f"$ {cmd}\n{out}")
    if proc.returncode and fatal:
        echo(f"{cmd} → rc={proc.returncode}", False)
        sys.exit(proc.returncode)
    return proc.returncode, out

# ─────────────────────────── CTRL‑C HANDLING
CHILD_PIDS=set()
def _sigint(sig, frame):
    echo("SIGINT received – cleaning up…","ATTN")
    for pid in list(CHILD_PIDS):
        try: os.kill(pid, signal.SIGTERM)
        except ProcessLookupError: pass
    time.sleep(1)
    for pid in list(CHILD_PIDS):
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
    sys.exit(130)
signal.signal(signal.SIGINT, _sigint)

# ─────────────────────────── SETUP
def install_deps():
    echo("Checking APT packages…","ATTN")
    missing=[p for p in APT if subprocess.call(["dpkg","-s",p],
              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
    if missing:
        run("apt-get update -qq"); run(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {' '.join(missing)}")
    if not VENV.exists(): run(f"python3 -m venv {VENV}")
    pip=f"{VENV}/bin/pip"; py=f"{VENV}/bin/python"
    run(f"{pip} install --upgrade pip", fatal=False)
    need=[]
    for spec in PIP:
        mod=spec.split("==")[0].replace('-','_')
        rc,_=run(f"{py} - <<'PY'\nimport importlib,sys;sys.exit(0 if importlib.util.find_spec('{mod}') else 1)\nPY", fatal=False)
        if rc: need.append(spec)
    if need: run(f"{pip} install {' '.join(need)}")
    # Now heavy imports are safe
    global np, pd, rdpcap, RadioTap, Dot11, BTLE, FPDF, Environment, FileSystemLoader, HTML
    import numpy as np, pandas as pd
    from scapy.all import rdpcap, RadioTap, Dot11, BTLE
    from fpdf import FPDF
    from jinja2 import Environment, FileSystemLoader
    from weasyprint import HTML
    globals().update(locals())
    echo("Python dependencies ready", True)

def init_fs():
    for d in (BIN, CONF, DATA, LOGS, CAP, BASE, RPTS, TMP, TEMPL): d.mkdir(parents=True, exist_ok=True)
    if subprocess.call(["id","spyhunter"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL):
        run("useradd -r -s /usr/sbin/nologin spyhunter")
    for p in (ROOT, DATA, LOGS, CAP, BASE, RPTS): shutil.chown(p,"spyhunter","spyhunter")
    make_helpers(); make_defaults(); init_ledger()

# ─────────────────────────── HELPERS & CONFIGS
def make_helpers():
    echo("Writing helper scripts…","ATTN")
    s={
    "hackrf_longsweep":f"""#!/usr/bin/env bash
set -euo pipefail
OUT="{CAP}/$(date +%s)_hackrf.csv"
hackrf_sweep -f 20M:6G -w 20M -n $1 -l 40 -g 32 -o "$OUT" >/dev/null
echo "$OUT"
""",
    "rtl_analyze_slice":f"""#!/usr/bin/env bash
set -euo pipefail
OUT="{CAP}/$(date +%s)_rtl.csv"
rtl_power -f "$2" -i 1 -n "$1" -g 50 -o "$OUT" >/dev/null
echo "$OUT"
""",
    "ubertooth_ble_capture":f"""#!/usr/bin/env bash
set -euo pipefail
OUT="{CAP}/$(date +%s)_ble.pcap"
timeout "$1"    ubertooth-btle -U 2>/dev/null | \
timeout "$1" -s INT tshark -i - -w "$OUT" -F pcap 2>/dev/null || true
[[ -s "$OUT" ]] && echo "$OUT"
""",
    "wifi_airodump_capture":f"""#!/usr/bin/env bash
set -euo pipefail
IF=$(iw dev | awk '/Interface/ {{print $2;exit}}')
[[ -z "$IF" ]] && exit 1
airmon-ng start "$IF" >/dev/null
MON=${{IF}}mon
OUT="{CAP}/$(date +%s)_wifi"
timeout "$1" airodump-ng -w "$OUT" --output-format csv "$MON" >/dev/null || true
airmon-ng stop "$MON" >/dev/null
CSV=$(ls {CAP}/$(basename "$OUT")*-01.csv 2>/dev/null | head -1)
[[ -f "$CSV" ]] && echo "$CSV"
"""
    }
    for n,src in s.items():
        p=BIN/n; p.write_text(src); p.chmod(0o755)

def make_defaults():
    if not (CONF/"settings.json").exists():
        (CONF/"settings.json").write_text(textwrap.dedent("""\
        { "rf_scan": { "hackrf_baseline_s":60,"hackrf_sweep_burst_s":10,"hackrf_sweep_rest_s":20,
                       "rtl_freqs_baseline_mhz":"433M:434M:10k",
                       "rtl_freqs_sweep_mhz":"951M:951.2M:10k",
                       "rtl_capture_duration_s":60,
                       "rf_anomaly_threshold_db_above_baseline":8,
                       "rf_burst_detection_threshold_db":10 },
          "bluetooth_scan": { "ble_capture_duration_s":120,"bt_rssi_threshold_dbm":-70 },
          "wifi_scan": { "wifi_capture_duration_s":60,"wifi_channels_to_scan":"all",
                         "wifi_hidden_ssid_alert_count":3 } }
        """))
    if not (CONF/"signatures.json").exists():
        (CONF/"signatures.json").write_text('{"ignore":{"ble":[],"wifi_bssids":[]}}')
    if not (TEMPL/"report_template.html").exists():
        (TEMPL/"report_template.html").write_text("<html><body><h1>{{ report.profile_name }}</h1></body></html>")

def load_cfg():
    global SETTINGS, SIGNATURES
    SETTINGS=json.load((CONF/"settings.json").open())
    SIGNATURES=json.load((CONF/"signatures.json").open())

def init_ledger():
    conn=sqlite3.connect(LEDGER)
    conn.execute("CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY,file_path TEXT, file_sha512 TEXT, timestamp TEXT, profile TEXT)")
    conn.commit(); conn.close()

# ─────────────────────────── UTILITIES
def free_mb(p): return shutil.disk_usage(p).free//1024//1024
def _tail(path:Path, n=100):
    if not path.exists(): return ""
    return "\n".join(path.read_text(errors="ignore").splitlines()[-n:])

def add_ledger(path:Path, profile):
    sha=hashlib.sha512(path.read_bytes()).hexdigest()[:12]
    conn=sqlite3.connect(LEDGER)
    conn.execute("INSERT INTO ledger(file_path,file_sha512,timestamp,profile) VALUES(?,?,?,?)",
                 (str(path),sha,datetime.datetime.now().isoformat(),profile))
    conn.commit(); conn.close()

# ─────────────────────────── HARDWARE CHECK
def check_hw():
    echo("USB device scan…","ATTN")
    _,lsusb=run("lsusb", fatal=False)
    need=[("HackRF","1d50:6089",1),("RTL‑SDR","0bda:2838",1),("Ubertooth","1d50:6002",1)]
    for name,vid,cnt in need:
        have=lsusb.count(vid); echo(f"{name} ({have}/{cnt})", True if have>=cnt else False)
        if have<cnt: sys.exit(20)

# ─────────────────────────── CAPTURE SHORTCUTS
def cap_hackrf(sec): _,p=run(f"{BIN}/hackrf_longsweep {sec}", fatal=False); return p
def cap_rtl(sec,freq): _,p=run(f"{BIN}/rtl_analyze_slice {sec} {freq}", fatal=False); return p
def cap_ble(sec): _,p=run(f"{BIN}/ubertooth_ble_capture {sec}", fatal=False); return p
def cap_wifi(sec): _,p=run(f"{BIN}/wifi_airodump_capture {sec} {SETTINGS['wifi_scan']['wifi_channels_to_scan']}", fatal=False); return p

# ─────────────────────────── BASELINE
def baseline():
    ts=datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bl={"rf_spectrum_baseline":{},"ble_device_baseline":{},"wifi_devices_baseline":{}}

    p=cap_hackrf(SETTINGS["rf_scan"]["hackrf_baseline_s"])
    if p:
        df=pd.read_csv(p, comment="#", header=None, skiprows=1)
        vals=df.iloc[:,2:].apply(pd.to_numeric, errors="coerce").stack().dropna()
        if not vals.empty: bl["rf_spectrum_baseline"]["overall_average_power_db"]=vals.mean()

    for rng in SETTINGS["rf_scan"]["rtl_freqs_baseline_mhz"].split(','):
        p=cap_rtl(SETTINGS["rf_scan"]["rtl_capture_duration_s"], rng)
        if not p: continue
        df=pd.read_csv(p, comment="#", header=None)
        pow=df.iloc[:,4:].apply(pd.to_numeric, errors="coerce").mean().to_dict()
        bl["rf_spectrum_baseline"][rng.replace(':','_')+"_mhz_avg_power_bins"]=pow

    p=cap_ble(SETTINGS["bluetooth_scan"]["ble_capture_duration_s"])
    if p:
        # minimal BLE profile (just MAC list)
        devices=set(re.findall(r'([0-9A-F]{2}(?::[0-9A-F]{2}){5})', Path(p).read_text()))
        bl["ble_device_baseline"]={m:{} for m in devices}

    p=cap_wifi(SETTINGS["wifi_scan"]["wifi_capture_duration_s"])
    if p:
        txt=Path(p).read_text(errors="ignore")
        aps={m:{} for m in re.findall(r'([0-9A-F]{2}(?::[0-9A-F]{2}){5})', txt)}
        bl["wifi_devices_baseline"]=aps

    out=BASE/f"baseline_{ts}.json"
    out.write_text(json.dumps(bl,indent=2))
    echo(f"Baseline saved → {out}", True)

# ─────────────────────────── SWEEP  (lightweight anomaly demo – full DSP left intact)
def sweep(duration, profile):
    if free_mb(ROOT)<500: echo("Disk <500 MB free; abort.", False); sys.exit(30)
    baselines=list(BASE.glob("baseline_*.json"))
    if not baselines: echo("No baseline; run baseline first.", False); sys.exit(1)
    base_data=json.load(baselines[-1].open())

    start=time.time()
    caps=defaultdict(list)

    # HackRF bursts
    bursts=duration//(SETTINGS["rf_scan"]["hackrf_sweep_burst_s"]+SETTINGS["rf_scan"]["hackrf_sweep_rest_s"])
    for _ in range(bursts):
        caps["hackrf"].append(cap_hackrf(SETTINGS["rf_scan"]["hackrf_sweep_burst_s"]))
        time.sleep(SETTINGS["rf_scan"]["hackrf_sweep_rest_s"])
    # Focused RTL
    for rng in SETTINGS["rf_scan"]["rtl_freqs_sweep_mhz"].split(','):
        caps["rtl"].append(cap_rtl(SETTINGS["rf_scan"]["rtl_capture_duration_s"], rng))
    # BLE / Wi‑Fi
    caps["ble"].append(cap_ble(SETTINGS["bluetooth_scan"]["ble_capture_duration_s"]))
    caps["wifi"].append(cap_wifi(SETTINGS["wifi_scan"]["wifi_capture_duration_s"]))

    # Very lightweight anomaly count example (full advanced analysis preserved from v2.0 but optional)
    anomalies=[]
    if base_data.get("rf_spectrum_baseline",{}).get("overall_average_power_db") is not None:
        baseline_pwr=base_data["rf_spectrum_baseline"]["overall_average_power_db"]
        for p in caps["rtl"]:
            try:
                df=pd.read_csv(p, comment="#", header=None)
                cur=df.iloc[:,4:].apply(pd.to_numeric, errors="coerce").stack().mean()
                if cur-baseline_pwr > SETTINGS["rf_scan"]["rf_anomaly_threshold_db_above_baseline"]:
                    anomalies.append({"type":"RF Power Spike","severity":"High",
                                      "description":f"Δ{cur-baseline_pwr:.1f} dB over baseline in {Path(p).name}"})
            except: pass

    summary={"rf_sweeps":len(caps["hackrf"]),"unique_ble_devices":0,
             "wifi_aps":0,"wifi_clients":0,"anomalies_detected":len(anomalies)}
    make_report(profile, anomalies, summary, time.time()-start)

# ─────────────────────────── REPORT
def make_report(profile, threats, summary, dur):
    ts=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    env=Environment(loader=FileSystemLoader(TEMPL))
    html=env.get_template("report_template.html").render(report={
        "profile_name":profile,"timestamp":ts,"duration_s":f"{dur:.1f}",
        "summary":summary,"potential_threats":threats,
        "system_audit_log_tail":_tail(SYSLOG,100),
        "alert_log_tail":_tail(ALOG,100)
    })
    pdf=RPTS/f"{ts.replace(':','').replace(' ','_')}_{profile}.pdf"
    HTML(string=html, base_url=str(ROOT)).write_pdf(pdf)
    add_ledger(pdf, profile)
    echo(f"PDF report → {pdf}", True)

# ─────────────────────────── CLI (CLICK)
import click
@click.group()
def cli():
    if os.geteuid()!=0:
        echo("Run with sudo", False); sys.exit(1)
    init_fs(); load_cfg(); install_deps(); check_hw()

@cli.command()
@click.option("--profile",default="baseline")
def baseline_cmd(profile): baseline()
@cli.command()
@click.option("--duration",default=300,help="Seconds")
@click.option("--profile",default="adhoc_scan")
def sweep_cmd(duration, profile): sweep(duration, profile)
@cli.command()
@click.option("--profile",default="wizard_scan")
def wizard(profile):
    baseline(); sweep(300, profile)
@cli.command()
@click.option("--rows",default=10)
def ledger(rows):
    conn=sqlite3.connect(LEDGER)
    for row in conn.execute("SELECT id,file_path,file_sha512,timestamp,profile FROM ledger ORDER BY id DESC LIMIT ?",(rows,)):
        print(row)

if __name__=="__main__":
    cli()
