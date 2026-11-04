#!/usr/bin/env python3
import argparse
import ctypes
import difflib
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

EXTS = {".exe", ".dll", ".sys", ".ocx", ".drv", ".scr", ".cpl"}

DEFAULT_CFG = {
    "trusted_publishers": {
        name: [] for name in [
            "Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Publisher",
            "Google LLC", "Google Inc.", "Mozilla Corporation",
            "Adobe Inc.", "Adobe Systems Incorporated", "Apple Inc.",
            "Intel Corporation", "NVIDIA Corporation", "Advanced Micro Devices, Inc.",
            "AMD", "Realtek Semiconductor Corp.", "Qualcomm Technologies, Inc.",
            "Dell Inc.", "HP Inc.", "Hewlett-Packard", "Lenovo",
            "ASUSTeK COMPUTER INC.", "ASUSTeK Computer Inc.", "Logitech Inc.",
            "Logitech", "Valve Corp.", "Valve Corporation", "Oracle America, Inc.",
            "Oracle Corporation", "VMware, Inc.", "VMware LLC", "Cisco Systems, Inc.",
            "Broadcom Inc.", "Samsung Electronics CO., LTD.",
            "Sony Interactive Entertainment Inc.", "Epic Games, Inc.",
            "Riot Games, Inc.", "Roblox Corporation", "Zoom Video Communications, Inc.",
            "Python Software Foundation", "VideoLAN", "The Document Foundation",
            "Audacity Team", "Igor Pavlov", "WinRAR GmbH", "Dropbox, Inc.",
            "Box, Inc.", "Slack Technologies, LLC", "GitHub, Inc.",
            "Atlassian Pty Ltd", "Cloudflare, Inc.", "Malwarebytes Inc.",
            "ESET, spol. s r.o.", "Bitdefender SRL", "Avast Software s.r.o.",
            "AVG Technologies USA, LLC", "Kaspersky Lab", "McAfee, LLC",
            "Fortinet, Inc.", "Trend Micro, Inc.", "Wacom Co., Ltd.",
            "Corsair Memory, Inc.", "Razer USA Ltd.", "SteelSeries ApS",
            "Electronic Arts, Inc.", "Ubisoft Entertainment", "Activision Publishing, Inc.",
            "Rockstar Games, Inc.", "CD Projekt S.A.", "GOG sp. z o.o."
        ]
    },
    "blocklist_thumbprints": [],
    "trusted_hashes": {"sha256": []},
    "blocklist_hashes": {"sha256": [], "sha1": [], "md5": []},
    "known_vulnerable_drivers": [
        "iqvw64e.sys", "gdrv.sys", "rtcore64.sys", "dbutil_2_3.sys", "capcom.sys",
    ],
}

PS_SCRIPT = r"""
param([Parameter(Mandatory=$true)][string]$InputFile)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$document = Get-Content -LiteralPath $InputFile -Raw -Encoding UTF8 | ConvertFrom-Json
$paths = @($document.paths)
$out = foreach ($p in $paths) {
  $p = [string]$p
  if ([string]::IsNullOrWhiteSpace($p)) {
    [pscustomobject]@{ Path = ''; Status = 'Error'; StatusMessage = 'Path kosong dalam input JSON.' }
    continue
  }
  try {
    $s = Get-AuthenticodeSignature -LiteralPath ([string]$p)
    $c = $s.SignerCertificate
    $ts = $s.TimeStamperCertificate
    $chain = $null
    $chainOk = $false
    $chainStatus = @()
    $root = $null
    if ($c) {
      $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
      $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
      $chainOk = [bool]$chain.Build($c)
      $chainStatus = @($chain.ChainStatus | ForEach-Object { [string]$_.Status })
      if ($chain.ChainElements.Count -gt 0) {
        $root = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
      }
    }
    $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo([string]$p)
    $fi = Get-Item -LiteralPath ([string]$p)
    [pscustomobject]@{
      Path = [string]$p
      FileSize = [int64]$fi.Length
      LastWriteTimeUtc = $fi.LastWriteTimeUtc.ToString('o')
      FileDescription = [string]$vi.FileDescription
      CompanyName = [string]$vi.CompanyName
      ProductName = [string]$vi.ProductName
      FileVersion = [string]$vi.FileVersion
      ProductVersion = [string]$vi.ProductVersion
      OriginalFilename = [string]$vi.OriginalFilename
      InternalName = [string]$vi.InternalName
      Language = [string]$vi.Language
      Status = [string]$s.Status
      StatusMessage = [string]$s.StatusMessage
      SignatureType = [string]$s.SignatureType
      Subject = if ($c) { $c.Subject } else { $null }
      Issuer = if ($c) { $c.Issuer } else { $null }
      Thumbprint = if ($c) { $c.Thumbprint } else { $null }
      NotBefore = if ($c) { $c.NotBefore.ToUniversalTime().ToString('o') } else { $null }
      NotAfter = if ($c) { $c.NotAfter.ToUniversalTime().ToString('o') } else { $null }
      Timestamped = [bool]$ts
      TimestampSubject = if ($ts) { $ts.Subject } else { $null }
      TimestampNotAfter = if ($ts) { $ts.NotAfter.ToUniversalTime().ToString('o') } else { $null }
      ChainValid = $chainOk
      ChainStatus = $chainStatus
      RootThumbprint = if ($root) { $root.Thumbprint } else { $null }
      RootSubject = if ($root) { $root.Subject } else { $null }
    }
  } catch {
    [pscustomobject]@{ Path = [string]$p; Status = 'Error'; StatusMessage = $_.Exception.Message }
  }
}
ConvertTo-Json -InputObject @($out) -Depth 4 -Compress
"""


def run_powershell(paths):
    if not paths:
        return []
    with tempfile.TemporaryDirectory() as tmp:
        ps1 = os.path.join(tmp, "check.ps1")
        lst = os.path.join(tmp, "paths.json")
        with open(ps1, "w", encoding="utf-8-sig") as f:
            f.write(PS_SCRIPT)
        with open(lst, "w", encoding="utf-8") as f:
            json.dump({"paths": [str(p) for p in paths]}, f, ensure_ascii=False)
        executable = "powershell.exe" if os.name == "nt" else "powershell"
        try:
            proc = subprocess.run(
                [executable, "-NoLogo", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-File", ps1, "-InputFile", lst],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=180,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("PowerShell timeout saat memeriksa signature.") from exc
        except OSError as exc:
            raise RuntimeError(f"Tidak bisa menjalankan PowerShell: {exc}") from exc
    if proc.returncode != 0 or not proc.stdout.strip():
        detail = (proc.stderr or proc.stdout or "Tidak ada detail error").strip()
        raise RuntimeError(f"PowerShell gagal (exit {proc.returncode}): {detail}")
    try:
        data = json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Output PowerShell bukan JSON valid: {proc.stdout[:500]}") from exc
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise RuntimeError("Format hasil PowerShell tidak dikenali.")
    if len(data) != len(paths):
        raise RuntimeError(
            f"Jumlah hasil PowerShell tidak sesuai: {len(data)} hasil untuk "
            f"{len(paths)} path. Periksa format input JSON dan PowerShell."
        )
    return data


def common_name(subject):
    if not subject:
        return ""
    m = re.search(r'(?:^|,)\s*CN=(?:"((?:[^"]|"")*)"|([^,]+))', subject, re.I)
    if not m:
        return ""
    return (m.group(1) if m.group(1) is not None else m.group(2)).replace('""', '"').strip()


def normalize(name):
    n = (name or "").casefold()
    for a, b in (("0", "o"), ("1", "l"), ("rn", "m"), ("vv", "w"), ("5", "s")):
        n = n.replace(a, b)
    return re.sub(r"[^a-z]", "", n)


def calculate_hashes(path):
    digests = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            for digest in digests.values():
                digest.update(chunk)
    return {name: digest.hexdigest().upper() for name, digest in digests.items()}


def circl_hashlookup(sha256, timeout=12):
    url = f"https://hashlookup.circl.lu/lookup/sha256/{sha256}"
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "SigCheck-HashLookup/1.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
            product = payload.get("ProductCode") or {}
            return {
                "status": "FOUND",
                "source": "CIRCL Hashlookup",
                "trust_score": payload.get("hashlookup:trust"),
                "database": payload.get("db"),
                "database_source": payload.get("source"),
                "file_name": payload.get("FileName"),
                "file_size": payload.get("FileSize"),
                "product_name": payload.get("ProductName") or product.get("ProductName"),
                "product_version": payload.get("ProductVersion") or product.get("ProductVersion"),
                "message": "Hash ditemukan pada database file yang dikenal"
            }
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {
                "status": "NOT_FOUND",
                "source": "CIRCL Hashlookup",
                "message": "Hash tidak ditemukan"
            }
        return {
            "status": "API_ERROR",
            "source": "CIRCL Hashlookup",
            "message": f"HTTP {exc.code}"
        }
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return {
            "status": "API_ERROR",
            "source": "CIRCL Hashlookup",
            "message": str(exc)
        }


def lookup_hashes_online(items, workers=5):
    results = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(circl_hashlookup, sha): path for path, sha in items}
        for future in as_completed(futures):
            path = futures[future]
            try:
                results[path] = future.result()
            except Exception as exc:
                results[path] = {
                    "status": "API_ERROR",
                    "source": "CIRCL Hashlookup",
                    "message": str(exc)
                }
    return results

def analyze(r, cfg, kernel=False):
    reasons = []
    status = (r.get("Status") or "Unknown").lower()
    subject = r.get("Subject") or ""
    publisher = common_name(subject)
    thumb = (r.get("Thumbprint") or "").replace(" ", "").upper()
    filename = os.path.basename(r.get("Path") or "").lower()

    if status == "valid":
        if thumb and thumb in {
            x.replace(" ", "").upper()
            for x in cfg.get("blocklist_thumbprints", [])
        }:
            return "BLOCKED_CERTIFICATE", ["Thumbprint sertifikat masuk blocklist."]

        trusted = cfg.get("trusted_publishers", {})
        trusted_names = list(trusted.keys())
        normalized_publisher = normalize(publisher)
        normalized_trusted = {normalize(x) for x in trusted_names}

        if normalized_publisher in normalized_trusted:
            return "TRUSTED", [
                "Authenticode valid dan publisher cocok dengan allowlist."
            ]

        close = difflib.get_close_matches(
            normalized_publisher,
            list(normalized_trusted),
            n=3,
            cutoff=0.78
        )
        if close:
            reasons.append(
                "Nama publisher mirip dengan publisher tepercaya; "
                "perlu pemeriksaan manual."
            )
        else:
            reasons.append(
                "Signature valid, tetapi publisher belum ada di allowlist."
            )
        return "VALID_SIGNATURE", reasons

    if status == "notsigned":
        reasons.append("File tidak memiliki digital signature Authenticode.")
        verdict = "UNSIGNED"
    elif status == "hashmismatch":
        reasons.append("Hash file tidak cocok dengan signature; file mungkin berubah.")
        verdict = "HASH_MISMATCH"
    elif status == "nottrusted":
        reasons.append("Signature tidak dipercaya oleh Windows.")
        verdict = "NOT_TRUSTED"
    elif status == "unknownerror":
        reasons.append(
            "Windows tidak dapat menentukan status signature. "
            "Ini bukan bukti otomatis bahwa file berbahaya."
        )
        verdict = "UNKNOWN"
    elif status == "error":
        reasons.append(r.get("StatusMessage") or "Gagal memeriksa file.")
        verdict = "ERROR"
    else:
        reasons.append(
            r.get("StatusMessage") or f"Status Authenticode: {r.get('Status')}"
        )
        verdict = "UNKNOWN"

    if kernel and filename in {
        x.lower() for x in cfg.get("known_vulnerable_drivers", [])
    }:
        reasons.append("Nama driver termasuk daftar driver rentan yang dikenal.")
        verdict = "KNOWN_VULNERABLE_DRIVER"

    return verdict, reasons


SEVERITY = [
    "BLOCKED_CERTIFICATE",
    "HASH_MISMATCH",
    "NOT_TRUSTED",
    "KNOWN_VULNERABLE_DRIVER",
    "UNSIGNED",
    "UNKNOWN",
    "ERROR",
    "VALID_SIGNATURE",
    "TRUSTED",
]

BAD = {
    "BLOCKED_CERTIFICATE",
    "HASH_MISMATCH",
    "NOT_TRUSTED",
    "KNOWN_VULNERABLE_DRIVER",
    "UNSIGNED",
}

VERDICT_COLOR = {
    "TRUSTED": "32",
    "VALID_SIGNATURE": "36",
    "UNSIGNED": "33",
    "UNKNOWN": "33",
    "ERROR": "31",
    "HASH_MISMATCH": "31",
    "NOT_TRUSTED": "31",
    "BLOCKED_CERTIFICATE": "31",
    "KNOWN_VULNERABLE_DRIVER": "31",
}


def paint(text, color, enabled=True):
    if not enabled:
        return str(text)
    return f"\033[{color}m{text}\033[0m"


USE_COLOR = True


def setup_console(no_color=False):
    global USE_COLOR
    USE_COLOR = not no_color and sys.stdout.isatty()
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass


def collect_files(target):
    found = []
    if os.path.isfile(target):
        if os.path.splitext(target)[1].lower() in EXTS:
            found.append(os.path.abspath(target))
        return found

    for root, _, files in os.walk(target):
        for name in files:
            if os.path.splitext(name)[1].lower() in EXTS:
                found.append(os.path.abspath(os.path.join(root, name)))
    return found


def loaded_drivers():
    command = [
        "driverquery",
        "/FO",
        "CSV",
        "/NH"
    ]
    proc = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or "driverquery gagal.")

    import csv
    from io import StringIO

    drivers = []
    for row in csv.reader(StringIO(proc.stdout)):
        if len(row) >= 3:
            path = row[1].strip()
            if path and path.lower().endswith(".sys"):
                if not os.path.isabs(path):
                    path = os.path.join(
                        os.environ.get("SystemRoot", r"C:\Windows"),
                        "System32",
                        "drivers",
                        os.path.basename(path)
                    )
                if os.path.isfile(path):
                    drivers.append(os.path.abspath(path))
    return drivers


def pid_modules(pid):
    try:
        import psutil
    except ImportError:
        raise RuntimeError(
            "Modul psutil belum terpasang. Jalankan: py -m pip install psutil"
        )

    process = psutil.Process(pid)
    modules = []
    for module in process.memory_maps():
        path = module.path
        if path and os.path.isfile(path):
            if os.path.splitext(path)[1].lower() in EXTS:
                modules.append(os.path.abspath(path))
    return modules


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ask(prompt, default=""):
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value if value else default


def yes_no(prompt, default=True):
    default_text = "Y/n" if default else "y/N"
    value = input(f"{prompt} ({default_text}): ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "ya"}


def parse_dropped_paths(raw):
    raw = raw.strip()
    if not raw:
        return []

    # Mendukung path yang dibungkus tanda kutip saat drag-and-drop.
    parts = re.findall(r'"([^"]+)"|(\S+)', raw)
    return [a or b for a, b in parts]


def pick_pid():
    try:
        import psutil
    except ImportError:
        print(paint(
            "Modul psutil belum terpasang. Jalankan: py -m pip install psutil",
            "33"
        ))
        return None

    name = ask("  Masukkan nama proses atau PID")
    if not name:
        return None

    if name.isdigit():
        return int(name)

    matches = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            if name.lower() in (p.info["name"] or "").lower():
                matches.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not matches:
        print(paint("  Proses tidak ditemukan.", "33"))
        return None

    if len(matches) == 1:
        p = matches[0].info
        print(f"  Dipilih: {p['name']} (PID {p['pid']})")
        return p["pid"]

    for i, p in enumerate(matches, 1):
        print(f"    {i}) {p.info['name']} (PID {p.info['pid']})")

    n = ask("  Pilih nomor", "1")
    try:
        return matches[int(n) - 1].info["pid"]
    except (ValueError, IndexError):
        print(paint("  Pilihan tidak valid.", "33"))
        return None
    
def interactive(base):
      a = argparse.Namespace(
        target=[],
        pid=None,
        drivers=False,
        config=base.config,
        json=base.json,
        only_bad=False,
        save=None,
        no_color=base.no_color
    )

      print()
      print(paint(
        "=== SigCheck: deteksi fake publisher / signature bypass ===",
        "36;1"
    ))

      if not is_admin():
        print(paint(
            "Catatan: tidak berjalan sebagai Administrator. "
            "Scan driver/proses bisa tidak lengkap.",
            "33"
        ))

      print()
      print("  1) Scan file / folder  (bisa seret & lepas ke jendela ini)")
      print("  2) Scan proses yang sedang berjalan  (PID atau nama)")
      print("  3) Scan kernel driver yang sedang di-load")
      print("  0) Keluar")
      print()

      tokens = set(
        re.split(
            r"[,\s]+",
            ask("Pilih (boleh lebih dari satu, mis. 1,3)", "3")
        )
    )

      if "0" in tokens:
        return None

      if "1" in tokens:
        print("  Seret file/folder ke sini lalu Enter (kosong = selesai):")
        while True:
            raw = ask("  >")
            if not raw:
                break
            for pth in parse_dropped_paths(raw):
                if os.path.exists(pth):
                    a.target.append(pth)
                    print(paint(f"    + {pth}", "32"))
                else:
                    print(paint(f"    ! tidak ditemukan: {pth}", "31"))

      if "2" in tokens:
        a.pid = pick_pid()

      if "3" in tokens:
        a.drivers = True

      if not (a.target or a.pid or a.drivers):
        print(paint("Tidak ada yang dipilih.", "33"))
        return a

      a.only_bad = yes_no("Tampilkan hanya yang bermasalah?", True)
      a.save = ask("Simpan hasil ke file JSON? (path, Enter = tidak)") or None
      print()
      return a

def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CFG))

    if not path:
        auto = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "trust.json"
        )
        if os.path.isfile(auto):
            path = auto
            print(f"[i] Memakai konfigurasi: {auto}")

    if path:
        with open(path, encoding="utf-8") as f:
            user = json.load(f)

        cfg["trusted_publishers"].update(
            user.get("trusted_publishers", {})
        )
        cfg["blocklist_thumbprints"] += user.get(
            "blocklist_thumbprints", []
        )
        cfg["known_vulnerable_drivers"] += user.get(
            "known_vulnerable_drivers", []
        )

        for key in ("trusted_hashes", "blocklist_hashes"):
            for algo, values in user.get(key, {}).items():
                cfg[key].setdefault(algo.lower(), [])
                cfg[key][algo.lower()] += values

    return cfg


def gather_files(a):
    files, drivers = [], []

    for target in a.target:
        if not os.path.exists(target):
            print(paint(f"[!] Tidak ditemukan: {target}", "31"))
            continue
        files += collect_files(target)

    if a.pid:
        try:
            files += pid_modules(a.pid)
        except Exception as exc:
            print(paint(
                f"[!] Gagal membaca proses {a.pid}: {exc} "
                "(coba jalankan sebagai Admin)",
                "31"
            ))

    if a.drivers:
        try:
            drivers = loaded_drivers()
            files += drivers
        except Exception as exc:
            print(paint(f"[!] Gagal enumerasi driver: {exc}", "31"))

    return sorted(set(files)), {d.lower() for d in drivers}


def print_results(results, a):
    if a.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    shown = [
        x for x in results
        if not (
            a.only_bad
            and x["verdict"] in {"TRUSTED", "VALID_SIGNATURE"}
        )
    ]

    shown.sort(
        key=lambda x: (
            SEVERITY.index(x["verdict"])
            if x["verdict"] in SEVERITY else 99
        )
    )

    for item in shown:
        tag = paint(
            f"[{item['verdict']:<17}]",
            VERDICT_COLOR.get(item["verdict"], "0"),
            USE_COLOR
        )
        print(f"{tag} {item['path']}")

        meta = item.get("metadata") or {}
        if meta.get("company_name") or meta.get("file_version"):
            print(
                f"      - Metadata: {meta.get('company_name') or '-'} | "
                f"{meta.get('file_description') or '-'} | "
                f"FileVersion {meta.get('file_version') or '-'}"
            )

        hashes = item.get("hashes") or {}
        if hashes:
            print(f"      - SHA256: {hashes.get('sha256', '-')}")

        db = item.get("hash_database") or {}
        if db:
            print(
                f"      - CIRCL Hashlookup: "
                f"{db.get('status', 'UNKNOWN')} | "
                f"{db.get('message', '')}"
            )
            if db.get("file_name"):
                print(
                    f"      - Database file: {db.get('file_name')} | "
                    f"Trust score: {db.get('trust_score', 'N/A')}"
                )

        if item["verdict"] not in {"TRUSTED", "VALID_SIGNATURE"}:
            for reason in item["reasons"]:
                print(f"      - {reason}")

    counts = {}
    for item in results:
        verdict = item["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1

    print()
    print(paint("Ringkasan", "1", USE_COLOR) + f": {len(results)} file diperiksa")

    for verdict in SEVERITY:
        if verdict in counts:
            print(
                "  "
                + paint(
                    f"{verdict:<18}",
                    VERDICT_COLOR.get(verdict, "0"),
                    USE_COLOR
                )
                + f" {counts[verdict]}"
            )


def run(a):
    cfg = load_config(a.config)
    files, driver_set = gather_files(a)

    if not files:
        print(paint("Tidak ada file untuk dicek.", "33", USE_COLOR))
        return 0

    print(f"Memeriksa {len(files)} file ... (bisa beberapa detik)")

    try:
        raw = run_powershell(files)
    except Exception as exc:
        print(paint(f"[!] {exc}", "31", USE_COLOR))
        return 2

    results = []
    lookup_items = []

    for record in raw:
        path = record.get("Path", "")
        verdict, reasons = analyze(
            record,
            cfg,
            kernel=path.lower() in driver_set
        )

        hashes = {}
        try:
            hashes = calculate_hashes(path)
            lookup_items.append((path, hashes["sha256"]))
        except (OSError, PermissionError) as exc:
            reasons.append(f"Gagal menghitung hash: {exc}")

        metadata = {
            "file_size": record.get("FileSize"),
            "last_write_time_utc": record.get("LastWriteTimeUtc"),
            "file_description": record.get("FileDescription"),
            "company_name": record.get("CompanyName"),
            "product_name": record.get("ProductName"),
            "file_version": record.get("FileVersion"),
            "product_version": record.get("ProductVersion"),
            "original_filename": record.get("OriginalFilename"),
            "internal_name": record.get("InternalName"),
            "language": record.get("Language"),
        }

        results.append({
            "path": path,
            "verdict": verdict,
            "reasons": reasons,
            "publisher": common_name(record.get("Subject")),
            "signer_subject": record.get("Subject"),
            "signer_issuer": record.get("Issuer"),
            "thumbprint": record.get("Thumbprint"),
            "certificate_not_before": record.get("NotBefore"),
            "certificate_not_after": record.get("NotAfter"),
            "authenticode_status": record.get("Status"),
            "authenticode_message": record.get("StatusMessage"),
            "signature_type": record.get("SignatureType"),
            "timestamped": record.get("Timestamped", False),
            "timestamp_publisher": record.get("TimestampSubject"),
            "timestamp_certificate_not_after": record.get("TimestampNotAfter"),
            "chain_valid_diagnostic": record.get("ChainValid"),
            "chain_status": record.get("ChainStatus", []),
            "root_subject": record.get("RootSubject"),
            "root_thumbprint": record.get("RootThumbprint"),
            "metadata": metadata,
            "hashes": hashes,
            "hash_database": {
                "status": "NOT_CHECKED",
                "message": "Menunggu lookup API"
            },
        })

    print(
        f"Lookup SHA-256 ke CIRCL Hashlookup "
        f"untuk {len(lookup_items)} file ..."
    )

    online = lookup_hashes_online(lookup_items) if lookup_items else {}

    for item in results:
        item["hash_database"] = online.get(
            item["path"],
            {
                "status": "API_ERROR",
                "source": "CIRCL Hashlookup",
                "message": "Hash tidak tersedia untuk lookup"
            }
        )

    print_results(results, a)

    if a.save:
        try:
            with open(a.save, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\nHasil disimpan ke {a.save}")
        except OSError as exc:
            print(paint(f"[!] Gagal menyimpan: {exc}", "31", USE_COLOR))

    return 1 if any(x["verdict"] in BAD for x in results) else 0


def main():
    ap = argparse.ArgumentParser(
        description=(
            "Cek digital signature: true vs fake publisher. "
            "Jalankan tanpa argumen untuk menu interaktif."
        )
    )

    ap.add_argument(
        "target",
        nargs="*",
        help="file atau folder (boleh lebih dari satu)"
    )
    ap.add_argument(
        "--pid",
        type=int,
        help="scan module yang di-load oleh PID"
    )
    ap.add_argument(
        "--drivers",
        action="store_true",
        help="scan semua kernel driver yang sedang di-load"
    )
    ap.add_argument(
        "--config",
        help="path trust.json (default: trust.json di folder script)"
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="output JSON"
    )
    ap.add_argument(
        "--only-bad",
        action="store_true",
        help="tampilkan yang bermasalah saja"
    )
    ap.add_argument(
        "--save",
        help="simpan hasil ke file JSON"
    )
    ap.add_argument(
        "--no-color",
        action="store_true",
        help="matikan warna"
    )

    a = ap.parse_args()

    if os.name != "nt":
        sys.exit("Tool ini hanya untuk Windows.")

    setup_console(a.no_color or a.json)

    if a.target or a.pid or a.drivers:
        sys.exit(run(a))

    if not sys.stdin.isatty():
        ap.error("isi target, --pid, atau --drivers")

    while True:
        opts = interactive(a)
        if opts is None:
            break

        if opts.target or opts.pid or opts.drivers:
            run(opts)

        print()
        if not yes_no("Scan lagi?", True):
            break

    ask("Tekan Enter untuk keluar")


if __name__ == "__main__":
    main()