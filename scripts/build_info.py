#!/usr/bin/env python3
"""
build_info.py

Collects, saves, and displays text summaries of build configurations and compiler flags
used for BoringSSL and Python binaries.
"""

import argparse
import datetime
import json
import os
import platform
import re
import subprocess
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def get_boringssl_info(ssl_root=None):
    """Read BoringSSL build metadata generated during build_boringssl.{sh,ps1}."""
    info = {
        "version": None,
        "commit_sha": None,
        "short_sha": None,
        "commit_date": None,
        "api_version": None,
        "build_type": None,
        "platform": None,
        "compiler": None,
    }

    if not ssl_root:
        return info

    meta_path = os.path.join(ssl_root, "BORINGSSL_METADATA.json")
    if os.path.isfile(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k in info:
                if k in data and data[k]:
                    info[k] = data[k]
        except Exception as e:
            info["error"] = str(e)

    # Fallback: read BORINGSSL_API_VERSION directly from base.h if metadata missing
    if not info["api_version"]:
        base_h = os.path.join(ssl_root, "include", "openssl", "base.h")
        if os.path.isfile(base_h):
            try:
                content = open(base_h, "r", encoding="utf-8", errors="ignore").read()
                m = re.search(r"^#define\s+BORINGSSL_API_VERSION\s+(\d+)", content, re.MULTILINE)
                if m:
                    info["api_version"] = m.group(1)
            except Exception:
                pass

    return info


def get_python_info(py_bin=None, env=None):
    """Query Python binary for compile configuration and sysconfig variables."""
    info = {
        "version": None,
        "build_tag": None,
        "compiler": None,
        "architecture": None,
        "bitness": None,
        "config_args": None,
        "cflags": None,
        "opt": None,
        "ldflags": None,
        "cc": None,
        "py_cflags": None,
        "ssl_version": None,
    }

    if not py_bin or not os.path.isfile(py_bin):
        return info

    query_script = """
import sys, ssl, platform, struct, json
try:
    import sysconfig
    sc_keys = ['CONFIG_ARGS', 'CFLAGS', 'OPT', 'CC', 'LDFLAGS', 'PY_CFLAGS', 'OPENSSL_INCLUDES', 'OPENSSL_LDFLAGS', 'OPENSSL_LIBS']
    sc = {k: sysconfig.get_config_var(k) for k in sc_keys if sysconfig.get_config_var(k)}
except Exception:
    sc = {}

data = {
    'version': sys.version.split()[0],
    'build_tag': sys.version,
    'compiler': platform.python_compiler(),
    'bitness': struct.calcsize('P') * 8,
    'machine': platform.machine(),
    'ssl_version': ssl.OPENSSL_VERSION,
    'sysconfig': sc
}
print('__JSON_START__' + json.dumps(data) + '__JSON_END__')
"""

    try:
        out = subprocess.check_output(
            [py_bin, "-c", query_script],
            env=env,
            stderr=subprocess.STDOUT,
        ).decode("utf-8", errors="replace")

        m = re.search(r"__JSON_START__(.*?)__JSON_END__", out, re.DOTALL)
        if m:
            data = json.loads(m.group(1))
            info["version"] = data.get("version")
            info["build_tag"] = data.get("build_tag")
            info["compiler"] = data.get("compiler")
            info["bitness"] = f"{data.get('bitness')}-bit"
            info["architecture"] = data.get("machine")
            info["ssl_version"] = data.get("ssl_version")
            sc = data.get("sysconfig", {})
            info["config_args"] = sc.get("CONFIG_ARGS")
            info["cflags"] = sc.get("CFLAGS")
            info["opt"] = sc.get("OPT")
            info["ldflags"] = sc.get("LDFLAGS")
            info["cc"] = sc.get("CC")
            info["py_cflags"] = sc.get("PY_CFLAGS")
            info["openssl_includes"] = sc.get("OPENSSL_INCLUDES")
            info["openssl_ldflags"] = sc.get("OPENSSL_LDFLAGS")
            info["openssl_libs"] = sc.get("OPENSSL_LIBS")
    except Exception as e:
        info["error"] = str(e)

    return info


def format_build_summary(py_info, bssl_info, runner_label=None, runner_arch=None, commit_sha=None):
    """Format dictionary info into human-readable monospace text summary."""
    lines = []
    bar = "=" * 80

    lines.append(bar)
    lines.append("Python + BoringSSL Build Configuration & Compiler Flags Summary")
    lines.append(bar)

    lines.append("\nPackage & Target Environment:")
    if py_info.get("version"):
        lines.append(f"  * Python Version:      {py_info['version']}")
    if bssl_info.get("version"):
        lines.append(f"  * BoringSSL Version:   {bssl_info['version']}")
    if py_info.get("ssl_version"):
        lines.append(f"  * Python ssl.VERSION:  {py_info['ssl_version']}")

    target_env = runner_label or platform.system()
    if runner_arch:
        target_env += f" ({runner_arch})"
    lines.append(f"  * Target Platform:     {target_env}")

    if py_info.get("architecture") or py_info.get("bitness"):
        arch_str = f"{py_info.get('architecture', 'unknown')} ({py_info.get('bitness', 'unknown')})"
        lines.append(f"  * Binary Architecture: {arch_str}")

    if commit_sha:
        lines.append(f"  * Repo Git Commit:     {commit_sha}")
    build_time = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.append(f"  * Generated At:        {build_time}")

    lines.append("\nBoringSSL Build Configuration:")
    if bssl_info.get("commit_sha"):
        lines.append(f"  * BoringSSL Commit:    {bssl_info['commit_sha']}")
    if bssl_info.get("commit_date"):
        lines.append(f"  * Commit Date:         {bssl_info['commit_date']}")
    if bssl_info.get("api_version"):
        lines.append(f"  * BORINGSSL_API_VER:   {bssl_info['api_version']}")
    if bssl_info.get("build_type"):
        lines.append(f"  * Build Options:       {bssl_info['build_type']}")
    if bssl_info.get("platform"):
        lines.append(f"  * Platform Target:     {bssl_info['platform']}")
    if bssl_info.get("compiler"):
        lines.append(f"  * Compiler:            {bssl_info['compiler']}")
    lines.append("  * TLS Hardening:       TLS 1.2+ floor (SSLv3/TLS 1.0/1.1 disabled via compat shim)")

    lines.append("\nPython Build Configuration & Flags:")
    if py_info.get("build_tag"):
        lines.append(f"  * Build Details:       {py_info['build_tag']}")
    if py_info.get("compiler"):
        lines.append(f"  * Compiler:            {py_info['compiler']}")
    if py_info.get("cc"):
        lines.append(f"  * C Compiler (CC):     {py_info['cc']}")
    if py_info.get("config_args"):
        lines.append(f"  * Configure Arguments: {py_info['config_args']}")
    if py_info.get("cflags"):
        lines.append(f"  * CFLAGS:              {py_info['cflags']}")
    if py_info.get("ldflags"):
        lines.append(f"  * LDFLAGS:             {py_info['ldflags']}")
    if py_info.get("openssl_libs"):
        lines.append(f"  * BoringSSL Link Libs: {py_info['openssl_libs']}")

    lines.append("\n" + bar + "\n")
    return "\n".join(lines)


def get_or_create_summary(install_dir, py_bin=None, ssl_root=None, runner_label=None, runner_arch=None, commit_sha=None):
    """Retrieve existing BUILD_INFO.txt from bundle or dynamically generate it."""
    search_dirs = [
        install_dir,
        os.path.join(install_dir, "python") if install_dir else None,
        os.path.join(install_dir, "ssl") if install_dir else None,
        ssl_root,
    ]
    for d in search_dirs:
        if d and os.path.isdir(d):
            for candidate_name in ["BUILD_INFO.txt", "BUILD_CONFIG.txt"]:
                fpath = os.path.join(d, candidate_name)
                if os.path.isfile(fpath):
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read().strip()
                            if content:
                                return content
                    except Exception:
                        pass

    py_info = get_python_info(py_bin=py_bin)
    bssl_info = get_boringssl_info(ssl_root=ssl_root)
    summary = format_build_summary(
        py_info=py_info,
        bssl_info=bssl_info,
        runner_label=runner_label,
        runner_arch=runner_arch,
        commit_sha=commit_sha,
    )

    if install_dir and os.path.isdir(install_dir):
        try:
            cache_path = os.path.join(install_dir, "BUILD_INFO.txt")
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(summary)
        except Exception:
            pass

    return summary


def main():
    parser = argparse.ArgumentParser(description="Generate and display Python + BoringSSL build summary.")
    parser.add_argument("--python-bin", help="Path to Python executable")
    parser.add_argument("--ssl-root", help="Root directory of BoringSSL installation")
    parser.add_argument("--install-dir", help="Installation root containing python and ssl directories")
    parser.add_argument("--runner-label", default=os.environ.get("RUNNER_LABEL"))
    parser.add_argument("--runner-arch", default=os.environ.get("RUNNER_ARCH"))
    parser.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--output", help="File path to save the generated text summary")
    parser.add_argument("--quiet", action="store_true", default=False)
    args = parser.parse_args()

    py_bin = args.python_bin
    ssl_root = args.ssl_root
    if args.install_dir and os.path.isdir(args.install_dir):
        if not py_bin:
            for cand in [
                os.path.join(args.install_dir, "python", "bin", "python3"),
                os.path.join(args.install_dir, "python", "python.exe"),
                os.path.join(args.install_dir, "bin", "python3"),
                os.path.join(args.install_dir, "python.exe"),
            ]:
                if os.path.isfile(cand):
                    py_bin = cand
                    break
        if not ssl_root:
            cand_ssl = os.path.join(args.install_dir, "ssl")
            if os.path.isdir(cand_ssl):
                ssl_root = cand_ssl

    py_info = get_python_info(py_bin=py_bin)
    bssl_info = get_boringssl_info(ssl_root=ssl_root)

    summary = format_build_summary(
        py_info=py_info,
        bssl_info=bssl_info,
        runner_label=args.runner_label,
        runner_arch=args.runner_arch,
        commit_sha=args.commit_sha,
    )

    if args.output:
        out_dir = os.path.dirname(os.path.abspath(args.output))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(summary)
        print(f"Build configuration summary written to: {args.output}")

    if not args.quiet:
        print(summary)


if __name__ == "__main__":
    main()
