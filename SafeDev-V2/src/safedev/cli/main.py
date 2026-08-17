"""SafeDev V2 — Security-Guarded Package Manager CLI.

Subcommands:
    safedev install <package>    # Scan & install (pip/npm)
    safedev upgrade <package>    # Scan & upgrade (pip/npm)
    safedev update <package>     # Alias for upgrade
    safedev uninstall <package>  # Safe uninstall (pip/npm)
    safedev remove <package>     # Alias for uninstall
    safedev list                 # List installed packages
    safedev scan <package>       # Scan ONLY (no install)
    safedev analyze <package>    # Alias for scan

Shortcut Options:
    safedev -p requests          # Scan & install PyPI package
    safedev -n express           # Scan & install npm package
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys

# Force IPv4 socket resolution to prevent Windows dual-stack IPv6 20-30 second timeouts
_orig_getaddrinfo = socket.getaddrinfo


def _getaddrinfo_ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
    try:
        return _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
    except Exception:
        return _orig_getaddrinfo(host, port, family, type, proto, flags)


socket.getaddrinfo = _getaddrinfo_ipv4_only

from safedev.core.config import SafeDevConfig
from safedev.core.models import AnalysisResult, Ecosystem, Verdict
from safedev.core.exceptions import SafeDevError
from safedev.ingestion.resolver import detect_ecosystem, parse_package_spec
from safedev.ingestion.fetcher import PackageFetcher
from safedev.inference.predictor import SafeDevPredictor
from safedev.reporting.formatter import format_json, format_text


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with subcommands and shortcut options."""
    parser = argparse.ArgumentParser(
        prog="safedev",
        description=(
            "SafeDev V2 — AI-Powered Security-Guarded Package Manager for Python & Node.js"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version="SafeDev 2.0.0",
    )

    # Shortcut options
    parser.add_argument(
        "-p", "--pypi",
        metavar="PACKAGE",
        help="Analyze & install a PyPI (Python) package",
    )
    parser.add_argument(
        "-n", "--npm",
        metavar="PACKAGE",
        help="Analyze & install an npm (JavaScript) package",
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Automatically confirm installation if verdict is SAFE",
    )
    parser.add_argument(
        "--no-install",
        action="store_true",
        help="Perform security scan ONLY without prompting to install",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        dest="output_format",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--model-dir",
        default=None,
        help="Path to model_artifacts directory",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="subcommand", help="Package management subcommands")

    # install
    cmd_install = subparsers.add_parser("install", help="Scan package for threats and install if safe")
    cmd_install.add_argument("package", help="Package name or specifier")
    cmd_install.add_argument("-p", "--pypi", action="store_true", help="Target PyPI ecosystem")
    cmd_install.add_argument("-n", "--npm", action="store_true", help="Target npm ecosystem")
    cmd_install.add_argument("-y", "--yes", action="store_true", help="Auto-confirm install if safe")

    # upgrade / update
    for sub_name in ["upgrade", "update"]:
        cmd_up = subparsers.add_parser(sub_name, help="Scan package for threats and upgrade/update")
        cmd_up.add_argument("package", help="Package name or specifier")
        cmd_up.add_argument("-p", "--pypi", action="store_true", help="Target PyPI ecosystem")
        cmd_up.add_argument("-n", "--npm", action="store_true", help="Target npm ecosystem")
        cmd_up.add_argument("-y", "--yes", action="store_true", help="Auto-confirm upgrade if safe")

    # uninstall / remove
    for sub_name in ["uninstall", "remove"]:
        cmd_un = subparsers.add_parser(sub_name, help="Uninstall a package from python or npm environment")
        cmd_un.add_argument("package", help="Package name")
        cmd_un.add_argument("-p", "--pypi", action="store_true", help="Uninstall from Python environment")
        cmd_un.add_argument("-n", "--npm", action="store_true", help="Uninstall from npm environment")

    # list
    cmd_list = subparsers.add_parser("list", help="List installed packages")
    cmd_list.add_argument("-p", "--pypi", action="store_true", help="List Python packages (pip list)")
    cmd_list.add_argument("-n", "--npm", action="store_true", help="List npm packages (npm list)")

    # scan / analyze / audit
    for sub_name in ["scan", "analyze", "audit"]:
        cmd_scan = subparsers.add_parser(sub_name, help="Perform security scan ONLY (no install)")
        cmd_scan.add_argument("package", help="Package name or specifier")
        cmd_scan.add_argument("-p", "--pypi", action="store_true", help="Target PyPI ecosystem")
        cmd_scan.add_argument("-n", "--npm", action="store_true", help="Target npm ecosystem")
        cmd_scan.add_argument("--format", choices=["text", "json"], default="text", dest="output_format")

    # Catch-all positional argument for direct package syntax (safedev requests)
    parser.add_argument(
        "positional",
        nargs="*",
        help=argparse.SUPPRESS,
    )

    return parser


def run_analysis(
    package_spec: str,
    ecosystem_hint: str | None = None,
    output_format: str = "text",
    model_dir: str | None = None,
) -> AnalysisResult:
    """Execute the analysis pipeline with live step-by-step progress output."""
    show_progress = (output_format == "text")

    if show_progress:
        print(f"\n\033[94m[1/5] [RESOLVE] Resolving package specification '{package_spec}'...\033[0m", flush=True)

    package_name, version = parse_package_spec(package_spec)
    ecosystem = detect_ecosystem(package_name, ecosystem_hint=ecosystem_hint)

    config = SafeDevConfig()
    if model_dir:
        from pathlib import Path
        config.model_dir = Path(model_dir)

    predictor = SafeDevPredictor(config)

    if show_progress:
        eco_label = "PyPI" if ecosystem == Ecosystem.PYPI else "npm"
        ver_str = f" v{version}" if version else " (latest)"
        print(f"\033[94m[2/5] [FETCH]   Fetching {eco_label} package artifact{ver_str}...\033[0m", flush=True)

    with PackageFetcher() as fetcher:
        if ecosystem == Ecosystem.PYPI:
            archive_bytes, filename = fetcher.fetch_pypi(package_name, version)
        else:
            archive_bytes, filename = fetcher.fetch_npm(package_name, version)

    size_mb = len(archive_bytes) / (1024 * 1024)
    if show_progress:
        print(f"\033[94m[3/5] [EXTRACT] Safe static extraction of '{filename}' ({size_mb:.2f} MB in memory)...\033[0m", flush=True)

    workers = min(16, (os.cpu_count() or 4) * 2)
    if show_progress:
        print(f"\033[94m[4/5] [PARALLEL] Multithreaded static feature extraction (using {workers} threads)...\033[0m", flush=True)

    if ecosystem == Ecosystem.PYPI:
        from safedev.analyzers.pypi.extractor import PyPIFeatureExtractor
        extractor = PyPIFeatureExtractor()
        features = extractor.extract_from_archive(archive_bytes, filename)

        if show_progress:
            print("\033[94m[5/5] [INFER]   Running XGBoost ML Classifier...\033[0m", flush=True)
        result = predictor.predict_pypi(features)
    else:
        from safedev.analyzers.npm.extractor import NpmFeatureExtractor
        extractor = NpmFeatureExtractor()
        features = extractor.extract_from_tarball(archive_bytes)

        if show_progress:
            print("\033[94m[5/5] [INFER]   Running GradientBoosting Classifier...\033[0m", flush=True)
        result = predictor.predict_npm(features)

    result.package_name = package_name
    result.version = version
    result.ecosystem = ecosystem

    return result


def prompt_and_execute(
    result: AnalysisResult,
    package_spec: str,
    action: str = "install",
    auto_yes: bool = False,
):
    """Prompt the user whether to proceed with package operation (install/upgrade)."""
    pkg_str = package_spec
    ecosystem = result.ecosystem
    action_title = action.capitalize()

    if result.verdict == Verdict.SAFE:
        print(f"\n\033[92m[+] SafeDev Security Check: PASSED (SAFE)\033[0m", flush=True)
        if auto_yes:
            proceed = True
        else:
            choice = input(
                f"\nDo you want to proceed with {action}ing '{pkg_str}'? [y/N]: "
            ).strip().lower()
            proceed = choice in ("y", "yes")

    elif result.verdict == Verdict.SUSPICIOUS:
        print(
            f"\n\033[93m[!] WARNING: '{pkg_str}' showed suspicious static security patterns.\033[0m",
            flush=True
        )
        choice = input(
            f"Do you still want to proceed with {action}ing '{pkg_str}'? [y/N]: "
        ).strip().lower()
        proceed = choice in ("y", "yes")

    elif result.verdict == Verdict.MALICIOUS:
        print(
            f"\n\033[91m[!] DANGER: '{pkg_str}' IS CLASSIFIED AS MALICIOUS! (Probability: {result.malicious_probability:.4f})\033[0m",
            flush=True
        )
        print("\033[91m    Operation is STRONGLY DISCOURAGED to protect your system.\033[0m", flush=True)
        choice = input(
            f"\nTo force {action} anyway, type '{action.upper()}': "
        ).strip()
        proceed = (choice == action.upper())

    else:
        print(f"\n\033[91m[!] Security analysis error: {result.error_message}\033[0m", flush=True)
        choice = input(
            f"Analysis failed. Do you want to force {action} '{pkg_str}' anyway? [y/N]: "
        ).strip().lower()
        proceed = choice in ("y", "yes")

    if not proceed:
        print(f"\n\033[94m[+] Operation aborted. SafeDev protected your environment.\033[0m", flush=True)
        return

    print(f"\n[+] Proceeding with {action} of '{pkg_str}'...", flush=True)
    if ecosystem == Ecosystem.PYPI:
        if action in ("upgrade", "update"):
            cmd = [sys.executable, "-m", "pip", "install", "--upgrade", pkg_str]
        else:
            cmd = [sys.executable, "-m", "pip", "install", pkg_str]
    else:
        if action in ("upgrade", "update"):
            cmd = ["npm", "update", pkg_str]
        else:
            cmd = ["npm", "install", pkg_str]

    try:
        res = subprocess.run(cmd)
        if res.returncode == 0:
            print(f"\033[92m[+] Successfully {action}ed '{pkg_str}'!\033[0m", flush=True)
        else:
            print(f"\033[91m[-] Package {action} failed with code {res.returncode}.\033[0m", flush=True)
    except Exception as e:
        print(f"\033[91m[-] Failed to launch package manager: {e}\033[0m", flush=True)


def handle_uninstall(package_spec: str, ecosystem_hint: str | None = None):
    """Execute package uninstallation safely."""
    package_name, _ = parse_package_spec(package_spec)
    ecosystem = detect_ecosystem(package_name, ecosystem_hint=ecosystem_hint)

    print(f"\n[+] Uninstalling '{package_spec}' ({ecosystem.value})...", flush=True)
    if ecosystem == Ecosystem.PYPI:
        cmd = [sys.executable, "-m", "pip", "uninstall", "-y", package_name]
    else:
        cmd = ["npm", "uninstall", package_name]

    try:
        res = subprocess.run(cmd)
        if res.returncode == 0:
            print(f"\033[92m[+] Successfully uninstalled '{package_spec}'!\033[0m", flush=True)
        else:
            print(f"\033[91m[-] Uninstall failed with code {res.returncode}.\033[0m", flush=True)
    except Exception as e:
        print(f"\033[91m[-] Failed to launch uninstaller: {e}\033[0m", flush=True)


def handle_list(ecosystem_hint: str | None = None):
    """List installed packages."""
    if ecosystem_hint and ecosystem_hint.lower() in ("npm", "node"):
        print("\n[+] Installed npm packages:", flush=True)
        subprocess.run(["npm", "list", "--depth=0"])
    else:
        print("\n[+] Installed Python packages (pip list):", flush=True)
        subprocess.run([sys.executable, "-m", "pip", "list"])


def main():
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    package_spec = None
    ecosystem_hint = None
    action = "install"
    scan_only = False

    # 1. Handle shortcuts -p / --pypi and -n / --npm
    if args.pypi:
        package_spec = args.pypi
        ecosystem_hint = "pypi"
    elif args.npm:
        package_spec = args.npm
        ecosystem_hint = "npm"

    # 2. Handle subcommands
    sub = args.subcommand
    if sub in ("install", "upgrade", "update", "uninstall", "remove", "scan", "analyze", "audit"):
        package_spec = getattr(args, "package", None) or package_spec
        if getattr(args, "pypi", False):
            ecosystem_hint = "pypi"
        elif getattr(args, "npm", False):
            ecosystem_hint = "npm"

        if sub in ("upgrade", "update"):
            action = "upgrade"
        elif sub in ("uninstall", "remove"):
            handle_uninstall(package_spec, ecosystem_hint)
            sys.exit(0)
        elif sub in ("scan", "analyze", "audit"):
            scan_only = True

    elif sub == "list":
        eco = "npm" if args.npm else ("pypi" if args.pypi else None)
        handle_list(eco)
        sys.exit(0)

    # 3. Handle direct positional arguments (safedev requests)
    elif args.positional and not package_spec:
        pos = args.positional
        package_spec = pos[0]

    if not package_spec:
        parser.print_help()
        sys.exit(1)

    if args.no_install:
        scan_only = True

    output_format = getattr(args, "output_format", "text")

    try:
        result = run_analysis(
            package_spec=package_spec,
            ecosystem_hint=ecosystem_hint,
            output_format=output_format,
            model_dir=args.model_dir,
        )

        if output_format == "json":
            print(format_json(result))
        else:
            print(format_text(result))

        if not scan_only and output_format == "text":
            prompt_and_execute(
                result=result,
                package_spec=package_spec,
                action=action,
                auto_yes=args.yes,
            )

        if result.verdict == Verdict.MALICIOUS:
            sys.exit(2)
        elif result.verdict == Verdict.SUSPICIOUS:
            sys.exit(1)
        elif result.verdict == Verdict.ANALYSIS_ERROR:
            sys.exit(3)
        else:
            sys.exit(0)

    except SafeDevError as e:
        error_result = AnalysisResult(
            package_name=package_spec,
            version=None,
            ecosystem=Ecosystem.PYPI,
            verdict=Verdict.ANALYSIS_ERROR,
            error_message=str(e),
        )
        if output_format == "json":
            print(format_json(error_result))
        else:
            print(format_text(error_result))
        sys.exit(3)

    except Exception as e:
        print(
            f"\n\033[91mSafeDev ANALYSIS_ERROR: {e}\033[0m",
            file=sys.stderr,
        )
        sys.exit(3)


if __name__ == "__main__":
    main()
