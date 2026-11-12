"""Scan local APKs or apps installed on a connected ADB device using Androguard."""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BACKEND_DIR)

from app.services.scanner.apk_static_engine import ANDROGUARD_AVAILABLE, apk_engine  # noqa: E402

TRUSTED_INSTALLERS = {
    "com.android.vending",
    "com.heytap.market",
    "com.oppo.market",
    "com.oplus.sau",
    "com.oplus.exsystemservice",
    "com.sec.android.app.samsungapps",
    "com.xiaomi.market",
    "com.amazon.venezia",
}


def find_adb_executable() -> str:
    default_adb = r"C:\Users\sharaf\AppData\Local\Android\Sdk\platform-tools\adb.exe"
    return default_adb if os.path.exists(default_adb) else "adb"


def list_adb_user_packages(adb: str, serial: Optional[str], include_system: bool) -> List[Dict[str, object]]:
    base_cmd = [adb] + (["-s", serial] if serial else [])
    flag = "-i" if include_system else "-3"
    pkg_cmd = base_cmd + ["shell", "pm", "list", "packages", "-f", "-i"]
    if not include_system:
        pkg_cmd.append("-3")

    res = subprocess.run(pkg_cmd, capture_output=True, text=True, check=True)
    packages = []
    for raw_line in res.stdout.splitlines():
        line = raw_line.strip()
        if not line.startswith("package:"):
            continue
        # Format: package:/data/app/.../base.apk=com.example.app  installer=com.android.vending
        body = line[len("package:"):]
        parts = body.split("installer=")
        path_and_pkg = parts[0].strip()
        installer = parts[1].strip() if len(parts) > 1 else "null"
        if "=" not in path_and_pkg:
            continue
        remote_apk_path, pkg_name = path_and_pkg.rsplit("=", 1)
        packages.append({
            "package_name": pkg_name.strip(),
            "remote_path": remote_apk_path.strip(),
            "installer": None if installer == "null" else installer,
            "is_trusted_store": installer in TRUSTED_INSTALLERS,
        })
    return packages


def scan_adb_device(serial: Optional[str], limit: int, include_system: bool, package_filter: Optional[str]) -> List[dict]:
    adb = find_adb_executable()
    packages = list_adb_user_packages(adb, serial, include_system)
    if package_filter:
        packages = [p for p in packages if package_filter.lower() in str(p["package_name"]).lower()]
    if limit > 0:
        packages = packages[:limit]

    base_cmd = [adb] + (["-s", serial] if serial else [])
    reports = []
    with tempfile.TemporaryDirectory(prefix="shieldguard_androguard_") as tmp_dir:
        for idx, pkg in enumerate(packages, 1):
            pkg_name = str(pkg["package_name"])
            remote_path = str(pkg["remote_path"])
            local_apk = os.path.join(tmp_dir, f"{pkg_name}.apk")
            print(f"[{idx}/{len(packages)}] Pulling & analyzing {pkg_name} ...", flush=True)
            pull = subprocess.run(base_cmd + ["pull", remote_path, local_apk], capture_output=True, text=True)
            if pull.returncode != 0 or not os.path.exists(local_apk):
                reports.append({
                    "package_name": pkg_name,
                    "verdict": "ERROR",
                    "risk_score": 0,
                    "error": pull.stderr.strip() or pull.stdout.strip(),
                })
                continue
            try:
                report = apk_engine.analyze_apk_file(local_apk, is_trusted_store=bool(pkg["is_trusted_store"]))
                report["installer"] = pkg["installer"]
                reports.append(report)
            except Exception as exc:
                reports.append({
                    "package_name": pkg_name,
                    "verdict": "ERROR",
                    "risk_score": 0,
                    "error": str(exc),
                })
            finally:
                if os.path.exists(local_apk):
                    try:
                        os.remove(local_apk)
                    except OSError:
                        pass
    return reports


def scan_local_paths(target_path: str) -> List[dict]:
    apk_files = []
    if os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for name in files:
                if name.lower().endswith(".apk"):
                    apk_files.append(os.path.join(root, name))
    elif os.path.isfile(target_path):
        apk_files.append(target_path)

    reports = []
    for idx, path in enumerate(apk_files, 1):
        print(f"[{idx}/{len(apk_files)}] Analyzing {path} ...", flush=True)
        try:
            reports.append(apk_engine.analyze_apk_file(path))
        except Exception as exc:
            reports.append({"package_name": os.path.basename(path), "verdict": "ERROR", "risk_score": 0, "error": str(exc)})
    return reports


def main():
    parser = argparse.ArgumentParser(description="ShieldGuard AI - Androguard APK Security Scanner")
    parser.add_argument("--adb", nargs="?", const="", default=None, help="Scan installed apps via ADB (optional serial)")
    parser.add_argument("--apk", help="Path to local APK file or directory of APKs")
    parser.add_argument("--limit", type=int, default=10, help="Max apps to pull from ADB (0 = all)")
    parser.add_argument("--system", action="store_true", help="Include system apps when using --adb")
    parser.add_argument("--filter", help="Substring filter for package names")
    parser.add_argument("--json-out", help="Optional path to save full JSON report")
    args = parser.parse_args()

    if not ANDROGUARD_AVAILABLE:
        print("ERROR: androguard is not installed in this Python environment.", file=sys.stderr)
        sys.exit(1)

    if args.adb is not None:
        serial = args.adb or None
        reports = scan_adb_device(serial, args.limit, args.system, args.filter)
    elif args.apk:
        reports = scan_local_paths(args.apk)
    else:
        parser.print_help()
        sys.exit(1)

    print("\n=== ANDROGUARD APK SCAN SUMMARY ===")
    for r in reports:
        if r.get("verdict") == "ERROR":
            print(f"[ERROR] {r['package_name']}: {r.get('error')}")
            continue
        print(
            f"[{r['verdict']:10s} | Score {r['risk_score']:3d}] {r.get('app_name') or r['package_name']} "
            f"({r['package_name']} v{r.get('version_name') or '?'}) "
            f"| DEX:{r.get('dex_count', 0)} Perms:{len(r.get('risky_permissions', []))} "
            f"APIs:{len(r.get('dangerous_apis', []))} URLs:{len(r.get('embedded_urls', []))}"
        )
        for beh in r.get("suspicious_behaviors", [])[:3]:
            print(f"    - {beh}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(reports, fh, indent=2)
        print(f"\nSaved JSON report to {args.json_out}")


if __name__ == "__main__":
    main()
