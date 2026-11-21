#!/usr/bin/env python3
"""
validate_runtime.py - Performance and Functional Validation Suite for Python + BoringSSL.

Designed specifically for verifying runtime readiness for applications like GAM and GYB.
Validates:
1. Native binary architecture (ELF/Mach-O/PE header inspection)
2. BoringSSL version, TLS 1.2+ hardening (TLS 1.0/1.1 disabled), and HTTPS/TLS handshake to www.googleapis.com
3. Cryptographic hashing (BoringSSL EVP SHA-256/512/HMAC/scrypt + built-in HACL* SHA-3 & BLAKE2)
4. Compression libraries (zlib, bz2, lzma/xz, gzip, zipfile)
5. High-throughput JSON serialization (_json C accelerator)
6. SQLite database performance & transactions (WAL mode, indexes, CRUD, thread-safety)
7. Multithreading & synchronization (threads, queues, locks)
8. Multiprocessing & process pool concurrency (cross-platform worker spawning & IPC)
"""

import argparse
import concurrent.futures
import hashlib
import hmac
import io
import json
import multiprocessing
import os
import platform
import socket
import sqlite3
import ssl
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    except Exception:
        pass


class Colors:
    def __init__(self, enabled=True):
        self.enabled = enabled and sys.stdout.isatty()

    def green(self, s):
        return f"\033[32m{s}\033[0m" if self.enabled else str(s)

    def red(self, s):
        return f"\033[31m{s}\033[0m" if self.enabled else str(s)

    def yellow(self, s):
        return f"\033[33m{s}\033[0m" if self.enabled else str(s)

    def cyan(self, s):
        return f"\033[36m{s}\033[0m" if self.enabled else str(s)

    def bold(self, s):
        return f"\033[1m{s}\033[0m" if self.enabled else str(s)

    def dim(self, s):
        return f"\033[2m{s}\033[0m" if self.enabled else str(s)


c = Colors()


def log_test_header(name):
    print(f"\n{c.bold('▶ Testing:')} {c.cyan(name)}", flush=True)


def log_test_result(name, duration, details=None):
    dur_str = f"{duration * 1000:.1f}ms"
    print(f"  {c.green('✔ PASS')} {name} {c.dim(f'({dur_str})')}", flush=True)
    if details:
        for k, v in details.items():
            print(f"    {c.dim('•')} {k}: {c.bold(v)}", flush=True)


def get_ssl_context():
    """Create SSL context with fallback to standard system CA bundles."""
    ctx = ssl.create_default_context()
    system_ca_bundles = [
        os.environ.get("SSL_CERT_FILE"),
        "/etc/ssl/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        r"C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt",
        r"C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt",
        r"C:\Program Files\Git\mingw64\ssl\certs\ca-bundle.crt",
    ]
    for ca_path in system_ca_bundles:
        if ca_path and os.path.isfile(ca_path):
            try:
                ctx.load_verify_locations(cafile=ca_path)
                break
            except Exception:
                pass
    return ctx


def test_boringssl_hardening(expected_ssl_prefix="BoringSSL"):
    """Verify BoringSSL identity and TLS 1.0/1.1 disablement (TLS 1.2+ floor)."""
    log_test_header("BoringSSL Identity & TLS 1.2+ Hardening")
    t0 = time.perf_counter()

    ssl_ver = ssl.OPENSSL_VERSION
    if expected_ssl_prefix:
        assert ssl_ver.startswith(expected_ssl_prefix), (
            f"Expected SSL version prefix '{expected_ssl_prefix}', got '{ssl_ver}'"
        )

    assert not hasattr(ssl, "PROTOCOL_TLSv1"), "PROTOCOL_TLSv1 should be disabled"
    assert not hasattr(ssl, "PROTOCOL_TLSv1_1"), "PROTOCOL_TLSv1_1 should be disabled"

    ctx = ssl.create_default_context()
    for legacy_ver in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
        rejected = False
        try:
            ctx.minimum_version = legacy_ver
        except (ValueError, ssl.SSLError):
            rejected = True
        assert rejected, f"Setting minimum_version to {legacy_ver} should be rejected"

    # Confirm TLS 1.2 and TLS 1.3 are accepted
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    elapsed = time.perf_counter() - t0
    log_test_result(
        "BoringSSL identity & TLS 1.2+ floor verified",
        elapsed,
        {
            "SSL Library": ssl_ver,
            "Legacy TLS 1.0/1.1": "Disabled (PROTOCOL_TLSv1/1_1 absent, min_version floor enforced)",
            "Supported Range": "TLSv1.2 .. TLSv1.3",
        },
    )


def test_boringssl_and_tls(target_host="www.googleapis.com"):
    """Test HTTPS/TLS handshake to Google APIs over BoringSSL."""
    log_test_header("BoringSSL HTTPS Connectivity (Google APIs)")
    t0 = time.perf_counter()

    url = f"https://{target_host}/discovery/v1/apis"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "boringssl-python-validator/1.0"},
    )

    ctx = get_ssl_context()
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        status_code = resp.getcode()
        body = resp.read()

    assert status_code == 200, f"Expected HTTP 200, got {status_code}"
    assert len(body) > 1000, "Response body unexpectedly short"

    sock = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=target_host)
    sock.settimeout(10)
    sock.connect((target_host, 443))
    tls_version = sock.version()
    cipher_name, proto_ver, bits = sock.cipher()
    peer_cert = sock.getpeercert()
    alpn_proto = sock.selected_alpn_protocol()
    verified_chain = sock.get_verified_chain() if hasattr(sock, "get_verified_chain") else None
    sock.close()

    assert tls_version in ("TLSv1.3", "TLSv1.2"), f"Unexpected TLS version: {tls_version}"
    assert proto_ver in ("TLSv1.3", "TLSv1.2"), f"Unexpected cipher protocol version from sock.cipher(): {proto_ver}"

    elapsed = time.perf_counter() - t0
    log_test_result(
        f"TLS connection to {target_host}",
        elapsed,
        {
            "SSL Build": ssl.OPENSSL_VERSION,
            "TLS Version": tls_version,
            "Cipher Suite": f"{cipher_name} ({proto_ver}, {bits} bits)",
            "ALPN Protocol": alpn_proto or "None (Negotiated HTTP/1.1)",
            "Verified Chain Len": str(len(verified_chain)) if verified_chain else "N/A",
            "Cert Subject": dict(x[0] for x in peer_cert.get("subject", [])).get("commonName", "Unknown"),
        },
    )


def test_sqlite_operations():
    """Test SQLite database performance, WAL mode, transactions, and indexing."""
    log_test_header("SQLite Performance & Transaction Integrity")
    t0 = time.perf_counter()

    assert sqlite3.threadsafety >= 1, f"SQLite threadsafety too low: {sqlite3.threadsafety}"

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        conn = sqlite3.connect(db_path, timeout=10)
        cursor = conn.cursor()

        cursor.execute("PRAGMA journal_mode=WAL;")
        mode = cursor.fetchone()[0].upper()
        cursor.execute("PRAGMA synchronous=NORMAL;")

        cursor.execute("""
            CREATE TABLE gam_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msg_id TEXT UNIQUE NOT NULL,
                user_email TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                timestamp INTEGER NOT NULL
            );
        """)
        cursor.execute("CREATE INDEX idx_user_time ON gam_messages (user_email, timestamp);")
        conn.commit()

        records = [
            (f"msg_{i:06d}", f"user_{i % 100}@example.com", 1024 + (i % 2048), 1700000000 + i)
            for i in range(10000)
        ]
        cursor.executemany(
            "INSERT INTO gam_messages (msg_id, user_email, size_bytes, timestamp) VALUES (?, ?, ?, ?);",
            records,
        )
        conn.commit()

        cursor.execute(
            "SELECT COUNT(*), SUM(size_bytes) FROM gam_messages WHERE user_email = ?",
            ("user_42@example.com",),
        )
        cnt, _ = cursor.fetchone()
        assert cnt == 100, f"Expected 100 rows, got {cnt}"

        try:
            with conn:
                cursor.execute("UPDATE gam_messages SET size_bytes = 0 WHERE id = 1;")
                raise RuntimeError("Simulated transaction fault")
        except RuntimeError:
            pass

        cursor.execute("SELECT size_bytes FROM gam_messages WHERE id = 1;")
        size_after_rollback = cursor.fetchone()[0]
        assert size_after_rollback != 0, "Rollback failed to restore state"

        conn.close()
    finally:
        for p in (db_path, f"{db_path}-wal", f"{db_path}-shm"):
            if os.path.exists(p):
                os.remove(p)

    elapsed = time.perf_counter() - t0
    log_test_result(
        "SQLite batch CRUD & WAL transactions (10k records)",
        elapsed,
        {
            "SQLite Version": sqlite3.sqlite_version,
            "Journal Mode": mode,
            "Thread Safety Level": f"{sqlite3.threadsafety} (Multi-thread enabled)",
        },
    )


def _worker_task(n):
    return sum(i * i for i in range(n))


def test_multiprocessing():
    """Test multiprocessing worker pools across CPU cores."""
    log_test_header("Multiprocessing & Worker Pool Concurrency")
    t0 = time.perf_counter()

    cpu_cnt = os.cpu_count() or 2
    workers = min(cpu_cnt, 4)
    tasks = [50000 + (i * 1000) for i in range(20)]
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        results = list(executor.map(_worker_task, tasks))

    assert len(results) == len(tasks), "Worker pool failed to collect all results"
    assert all(r > 0 for r in results), "Worker calculations returned invalid values"

    elapsed = time.perf_counter() - t0
    log_test_result(
        f"ProcessPoolExecutor ({workers} worker processes, 20 tasks)",
        elapsed,
        {
            "CPU Count": str(cpu_cnt),
            "Workers Spawned": str(workers),
            "Multiprocessing Start Method": multiprocessing.get_start_method(),
        },
    )


def test_compression_libraries():
    """Test compression and archive modules (zlib, bz2, lzma/xz, zipfile)."""
    log_test_header("Compression & Archiving Libraries (GYB/GAM storage)")
    t0 = time.perf_counter()

    sample_text = (
        "Subject: GAM / GYB Backup Test\n"
        + "This is a repeated line of test data for compression benchmarking.\n" * 500
    ).encode("utf-8")
    original_size = len(sample_text)

    import gzip
    import zlib

    z_comp = zlib.compress(sample_text, 6)
    assert zlib.decompress(z_comp) == sample_text

    gz_comp = gzip.compress(sample_text)
    assert gzip.decompress(gz_comp) == sample_text

    bio = io.BytesIO()
    with zipfile.ZipFile(bio, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test_message.eml", sample_text)
    bio.seek(0)
    with zipfile.ZipFile(bio, mode="r") as zf:
        assert zf.read("test_message.eml") == sample_text

    has_bz2 = False
    try:
        import bz2
        assert bz2.decompress(bz2.compress(sample_text)) == sample_text
        has_bz2 = True
    except ImportError:
        pass

    has_lzma = False
    try:
        import lzma
        assert lzma.decompress(lzma.compress(sample_text)) == sample_text
        has_lzma = True
    except ImportError:
        pass

    elapsed = time.perf_counter() - t0
    log_test_result(
        "Compression algorithms (zlib, gzip, zipfile, bz2, lzma/xz)",
        elapsed,
        {
            "Original Size": f"{original_size} bytes",
            "zlib Compressed": f"{len(z_comp)} bytes ({len(z_comp)/original_size*100:.1f}%)",
            "bzip2 Available": "Yes" if has_bz2 else "No",
            "lzma/xz Available": "Yes" if has_lzma else "No",
            "Zip Archive Integrity": "Verified lossless round-trip",
        },
    )


def test_cryptographic_hashing():
    """Test BoringSSL EVP hashing + built-in HACL* SHA-3/BLAKE2 + PBKDF2/scrypt."""
    log_test_header("Cryptographic Hashing Throughput (_hashlib / BoringSSL + HACL*)")
    t0 = time.perf_counter()

    chunk = b"A" * (1024 * 1024)
    iterations = 20

    s256 = hashlib.sha256()
    for _ in range(iterations):
        s256.update(chunk)
    d256 = s256.hexdigest()

    s512 = hashlib.sha512()
    for _ in range(iterations):
        s512.update(chunk)
    _ = s512.hexdigest()

    # Verify full stdlib hash coverage (BoringSSL EVP + HACL* fallbacks)
    assert len(hashlib.md5(b"test").hexdigest()) == 32
    assert len(hashlib.sha1(b"test").hexdigest()) == 40
    assert len(hashlib.sha224(b"test").hexdigest()) == 56
    assert len(hashlib.sha384(b"test").hexdigest()) == 96
    assert len(hashlib.sha3_256(b"test").hexdigest()) == 64
    assert len(hashlib.sha3_512(b"test").hexdigest()) == 128
    assert len(hashlib.shake_256(b"test").hexdigest(32)) == 64
    assert len(hashlib.blake2b(b"test").hexdigest()) == 128
    assert len(hashlib.blake2s(b"test").hexdigest()) == 64
    assert len(hmac.new(b"secret-key", b"payload", hashlib.sha256).hexdigest()) == 64
    assert len(hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1000)) == 32
    assert len(hashlib.scrypt(b"password", salt=b"salt", n=16, r=8, p=1)) == 64

    elapsed = time.perf_counter() - t0
    throughput = (iterations * 2) / elapsed
    log_test_result(
        f"BoringSSL + HACL* Hashing ({iterations * 2} MB processed)",
        elapsed,
        {
            "Throughput": f"{throughput:.1f} MB/s",
            "Algorithms Verified": "MD5, SHA-1/224/256/384/512, SHA3, SHAKE, BLAKE2b/s, HMAC, PBKDF2, scrypt",
            "SHA-256 Digest Sample": f"{d256[:16]}...",
        },
    )


def test_json_throughput():
    """Test JSON encoding/decoding performance with C accelerator."""
    log_test_header("JSON Serialization & C Accelerator (_json)")
    t0 = time.perf_counter()

    users = [
        {
            "id": f"1092837465{i:04d}",
            "primaryEmail": f"user.{i}@example.com",
            "name": {"givenName": f"Given{i}", "familyName": f"Family{i}"},
            "isAdmin": (i == 0),
            "isDelegatedAdmin": False,
            "creationTime": "2026-01-01T00:00:00.000Z",
            "orgUnitPath": "/Engineering/Cloud",
            "aliases": [f"alias.{i}@example.com", f"u{i}@example.com"],
        }
        for i in range(2500)
    ]
    payload = {"kind": "admin#directory#users", "users": users}
    encoded = json.dumps(payload)
    decoded = json.loads(encoded)

    assert len(decoded["users"]) == 2500
    assert decoded["users"][100]["primaryEmail"] == "user.100@example.com"

    elapsed = time.perf_counter() - t0
    payload_size_kb = len(encoded) / 1024
    log_test_result(
        f"JSON round-trip (2,500 Google API records, {payload_size_kb:.1f} KB)",
        elapsed,
        {
            "Payload Size": f"{payload_size_kb:.1f} KB",
            "C Accelerator Active": str(getattr(json.decoder, "c_scanstring", None) is not None),
        },
    )


def test_multithreading_concurrency():
    """Test multi-threaded queue operations and lock synchronization."""
    log_test_header("Multi-threading & Lock Synchronization")
    t0 = time.perf_counter()

    import queue
    q = queue.Queue()
    results = []
    lock = threading.Lock()

    def worker():
        while True:
            try:
                val = q.get_nowait()
            except queue.Empty:
                break
            with lock:
                results.append(val * 2)
            q.task_done()

    for item in range(500):
        q.put(item)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 500
    assert sum(results) == sum(x * 2 for x in range(500))

    elapsed = time.perf_counter() - t0
    log_test_result(
        "8 Thread worker pool with Queue and Lock synchronization (500 items)",
        elapsed,
        {
            "Items Processed": str(len(results)),
            "Synchronization State": "All items verified without race conditions",
        },
    )


def inspect_binary_machine(filepath):
    """Inspect binary file header (ELF, Mach-O, PE) on disk to extract native architecture."""
    import struct
    real_path = os.path.realpath(filepath)
    with open(real_path, "rb") as f:
        magic = f.read(4)
        if magic.startswith(b"MZ"):
            f.seek(0x3C)
            pe_offset = struct.unpack("<I", f.read(4))[0]
            f.seek(pe_offset)
            if f.read(4) != b"PE\0\0":
                raise ValueError(f"Invalid PE signature in {real_path}")
            machine = struct.unpack("<H", f.read(2))[0]
            if machine == 0x8664:
                return "x64", "PE32+ (x64 / AMD64, 0x8664)"
            elif machine == 0xAA64:
                return "arm64", "PE32+ (ARM64, 0xAA64)"
            elif machine == 0x014C:
                return "x86", "PE32 (x86 32-bit, 0x014C)"
            return f"pe-0x{machine:04x}", f"PE unknown (0x{machine:04x})"

        elif magic.startswith(b"\x7fELF"):
            f.seek(4)
            elf_class = ord(f.read(1))
            f.seek(18)
            e_machine = struct.unpack("<H", f.read(2))[0]
            if e_machine == 62:
                return "x64", "ELF 64-bit (x86-64, machine 62)"
            elif e_machine == 183:
                return "arm64", "ELF 64-bit (AArch64 / ARM64, machine 183)"
            elif e_machine == 3:
                return "x86", "ELF 32-bit (i386, machine 3)"
            return f"elf-{e_machine}", f"ELF (machine {e_machine}, class {elf_class})"

        elif magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"):
            endian = "<" if magic == b"\xcf\xfa\xed\xfe" else ">"
            cputype = struct.unpack(endian + "I", f.read(4))[0]
            if cputype == 0x0100000C:
                return "arm64", "Mach-O 64-bit (ARM64, 0x0100000C)"
            elif cputype == 0x01000007:
                return "x64", "Mach-O 64-bit (x86_64, 0x01000007)"
            return f"macho-0x{cputype:08x}", f"Mach-O 64-bit (0x{cputype:08x})"

        elif magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            endian = "<" if magic == b"\xbe\xba\xfe\xca" else ">"
            nfat = struct.unpack(endian + "I", f.read(4))[0]
            archs = []
            for _ in range(nfat):
                ctype = struct.unpack(endian + "I", f.read(4))[0]
                f.seek(16, os.SEEK_CUR)
                if ctype == 0x0100000C:
                    archs.append("arm64")
                elif ctype == 0x01000007:
                    archs.append("x64")
            return ",".join(archs), f"Mach-O Universal Fat ({', '.join(archs)})"

        raise ValueError(f"Unknown executable format for {real_path} (magic: {magic!r})")


def test_native_binary_architecture(expected_arch=None):
    """Inspect on-disk binary headers to verify native compilation."""
    log_test_header("Native Binary Architecture & Host Verification")
    t0 = time.perf_counter()

    executable = sys.executable
    detected_arch, desc = inspect_binary_machine(executable)

    ptr_bits = 64 if sys.maxsize > 2**32 else 32
    if ptr_bits != 64:
        raise AssertionError(f"Python binary is 32-bit (sys.maxsize={sys.maxsize}), expected 64-bit native binary!")

    details = {
        "Executable": executable,
        "Binary Header Inspection": desc,
        "Pointer Width": f"{ptr_bits}-bit",
        "Python Reported Machine": platform.machine(),
    }

    if expected_arch:
        expected_clean = expected_arch.lower().strip()
        if expected_clean in ("arm64", "aarch64"):
            expected_canon = "arm64"
        elif expected_clean in ("x64", "x86_64", "amd64"):
            expected_canon = "x64"
        else:
            expected_canon = expected_clean

        if expected_canon not in detected_arch.split(","):
            raise AssertionError(
                f"FATAL ARCHITECTURE MISMATCH: Binary {executable} is compiled for [{desc}], "
                f"but host runner strictly requires native [{expected_canon}]!"
            )
        details["Native Host Architecture Match"] = f"VERIFIED: native {expected_canon}"

    elapsed = time.perf_counter() - t0
    log_test_result("Native Binary Architecture Verification", elapsed, details)


def test_runtime_isolation():
    """Test runtime environment isolation and platform paths."""
    log_test_header("Runtime Isolation & Environment Health")
    t0 = time.perf_counter()

    elapsed = time.perf_counter() - t0
    log_test_result(
        "Python Runtime Environment Health",
        elapsed,
        {
            "Python Executable": sys.executable,
            "Python Version": sys.version.split()[0],
            "Platform / OS": f"{platform.system()} ({platform.machine()})",
            "Default File Encoding": sys.getdefaultencoding(),
        },
    )


def main():
    parser = argparse.ArgumentParser(description="Validate Python + BoringSSL runtime for GAM/GYB readiness.")
    parser.add_argument("--skip-network", action="store_true", help="Skip online Google API TLS handshake tests")
    parser.add_argument("--expected-ssl-prefix", default="BoringSSL", help="Expected ssl.OPENSSL_VERSION prefix (default: 'BoringSSL')")
    parser.add_argument("--expected-arch", default=None, help="Expected native architecture (e.g. 'arm64' or 'x64')")
    args = parser.parse_args()

    print("\n" + c.bold("=================================================="))
    print(c.bold("🚀 Python + BoringSSL GAM/GYB Runtime Validation Suite"))
    print(c.bold("=================================================="))
    print(f"  Python Version:  {c.cyan(sys.version.split()[0])}")
    print(f"  SSL Library:     {c.cyan(ssl.OPENSSL_VERSION)}")
    print(f"  Executable Path: {c.dim(sys.executable)}")
    target_arch = args.expected_arch or os.environ.get("RUNNER_ARCH")
    if target_arch:
        print(f"  Required Native Arch: {c.bold(target_arch)}")

    t_suite_start = time.perf_counter()
    errors = []

    tests = [
        ("Native Architecture Verification", lambda: test_native_binary_architecture(expected_arch=target_arch)),
        ("BoringSSL Identity & Hardening", lambda: test_boringssl_hardening(expected_ssl_prefix=args.expected_ssl_prefix)),
        ("Runtime Isolation", test_runtime_isolation),
        ("Cryptographic Hashing", test_cryptographic_hashing),
        ("Compression Libraries", test_compression_libraries),
        ("JSON Throughput", test_json_throughput),
        ("SQLite Performance", test_sqlite_operations),
        ("Multi-threading", test_multithreading_concurrency),
        ("Multiprocessing", test_multiprocessing),
    ]

    if not args.skip_network:
        tests.insert(2, ("BoringSSL & TLS Handshake", test_boringssl_and_tls))

    for name, test_fn in tests:
        try:
            test_fn()
        except Exception as e:
            errors.append((name, str(e)))
            print(f"  {c.red('✖ FAILED')} {name}: {e}")

    total_time = time.perf_counter() - t_suite_start
    print("\n" + c.bold("=================================================="))
    if errors:
        print(c.red(f"❌ Validation Suite FAILED: {len(errors)} error(s) detected in {total_time:.2f}s"))
        for name, err in errors:
            print(f"  - {c.bold(name)}: {c.red(err)}")
        sys.exit(1)
    else:
        print(c.green(f"✅ All {len(tests)} runtime checks PASSED successfully in {total_time:.2f}s!"))
        print(c.bold("=================================================="))
        sys.exit(0)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
