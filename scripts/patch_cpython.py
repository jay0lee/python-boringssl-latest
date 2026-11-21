#!/usr/bin/env python3
"""
patch_cpython.py - Dynamically adapts CPython to compile and link against BoringSSL HEAD.

Strategy (designed to survive both BoringSSL HEAD churn and new CPython releases):
1. Probes the freshly compiled BoringSSL installation (using the C compiler when available,
   falling back to header inspection) to discover exactly which OpenSSL APIs/signatures
   are present or absent in this BoringSSL commit.
2. Generates a tailored `<boringssl>/include/boringssl_compat.h` containing ONLY the shims
   needed for this BoringSSL build, plus a no-patch TLS 1.2+ floor (disabling SSLv3/TLS 1.0/1.1).
3. Performs minimal semantic (non-line-number) injections in CPython:
   - Inserts `#include "boringssl_compat.h"` in Modules/_ssl.c and Modules/_hashopenssl.c
     right after their OpenSSL includes (before `#ifndef OPENSSL_THREADS`).
   - Relaxes `configure`'s `NID_sha3_512` check in `ac_cv_working_openssl_hashlib`
     (since BoringSSL omits SHA-3 NIDs and CPython builds SHA-3/BLAKE2 via HACL*).
   - Optionally configures static linking in `Modules/Setup` on Linux to hide BoringSSL symbols.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def detect_compiler(explicit=None):
    if explicit:
        return explicit
    for env_var in ("CC",):
        val = os.environ.get(env_var)
        if val:
            cmd = val.split()[0]
            if shutil.which(cmd):
                return cmd
    if os.name == "nt":
        for cand in ("cl", "clang-cl", "clang", "gcc"):
            if shutil.which(cand):
                return cand
    else:
        for cand in ("cc", "clang", "gcc"):
            if shutil.which(cand):
                return cand
    return None


def probe_c_snippet(compiler, include_dir, snippet):
    """Return True if C snippet compiles syntactically cleanly against BoringSSL headers."""
    if not compiler:
        return None
    compiler_base = os.path.basename(compiler).lower()
    is_msvc = compiler_base in ("cl", "cl.exe", "clang-cl", "clang-cl.exe")

    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "probe.c"
        src.write_text(snippet, encoding="utf-8")
        if is_msvc:
            # /we4013 is required so MSVC treats implicit function declarations (C4013) as an error,
            # matching GCC/Clang's -Werror=implicit-function-declaration.
            cmd = [compiler, "/nologo", "/Zs", "/we4013", f"/I{include_dir}", str(src)]
        else:
            cmd = [
                compiler,
                "-fsyntax-only",
                "-Werror=implicit-function-declaration",
                f"-I{include_dir}",
                str(src),
            ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return proc.returncode == 0


def header_contains(include_dir, pattern):
    openssl_dir = Path(include_dir) / "openssl"
    if not openssl_dir.is_dir():
        return False
    rx = re.compile(pattern)
    for hdr in openssl_dir.glob("*.h"):
        try:
            if rx.search(hdr.read_text(encoding="utf-8", errors="ignore")):
                return True
        except OSError:
            continue
    return False


def probe_capabilities(boringssl_dir, compiler=None):
    """Probe the installed BoringSSL headers/compiler for OpenSSL compatibility gaps."""
    include_dir = Path(boringssl_dir) / "include"
    if not (include_dir / "openssl" / "ssl.h").is_file():
        raise FileNotFoundError(f"BoringSSL headers not found under {include_dir}")

    probes = {
        "has_set_ciphersuites": (
            """
            #include <openssl/ssl.h>
            int test(SSL_CTX *ctx) { return SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256"); }
            """,
            r"\bSSL_CTX_set_ciphersuites\s*\(",
        ),
        "has_get_security_level": (
            """
            #include <openssl/ssl.h>
            int test(const SSL_CTX *ctx) { return SSL_CTX_get_security_level(ctx); }
            """,
            r"\bSSL_CTX_get_security_level\s*\(",
        ),
        "has_get0_verified_chain": (
            """
            #include <openssl/ssl.h>
            STACK_OF(X509) *test(const SSL *ssl) { return SSL_get0_verified_chain(ssl); }
            """,
            r"\bSSL_get0_verified_chain\s*\(",
        ),
        "has_get_client_ciphers": (
            """
            #include <openssl/ssl.h>
            STACK_OF(SSL_CIPHER) *test(const SSL *ssl) { return SSL_get_client_ciphers(ssl); }
            """,
            r"\bSSL_get_client_ciphers\s*\(",
        ),
        "has_2arg_sk_ssl_cipher_find": (
            """
            #include <openssl/ssl.h>
            int test(const STACK_OF(SSL_CIPHER) *sk, const SSL_CIPHER *c) {
                return sk_SSL_CIPHER_find(sk, c);
            }
            """,
            r"NO_HEADER_FALLBACK",
        ),
        "has_set1_sigalgs_list": (
            """
            #include <openssl/ssl.h>
            int test(SSL_CTX *ctx) { return SSL_CTX_set1_sigalgs_list(ctx, "RSA+SHA256"); }
            """,
            r"\bSSL_CTX_set1_sigalgs_list\s*\(",
        ),
        "has_set1_client_sigalgs_list": (
            """
            #include <openssl/ssl.h>
            int test(SSL_CTX *ctx) { return SSL_CTX_set1_client_sigalgs_list(ctx, "RSA+SHA256"); }
            """,
            r"\bSSL_CTX_set1_client_sigalgs_list\s*\(",
        ),
        "has_sha3_512_nid": (
            """
            #include <openssl/objects.h>
            const char *test(void) { return OBJ_nid2sn(NID_sha3_512); }
            """,
            r"\bNID_sha3_512\b",
        ),
        "has_ssl_ctx_set_num_tickets": (
            """
            #include <openssl/ssl.h>
            int test(SSL_CTX *ctx) { return SSL_CTX_set_num_tickets(ctx, 2); }
            """,
            r"\bSSL_CTX_set_num_tickets\s*\(",
        ),
        "has_ssl_ctx_get_num_tickets": (
            """
            #include <openssl/ssl.h>
            size_t test(const SSL_CTX *ctx) { return SSL_CTX_get_num_tickets(ctx); }
            """,
            r"\bSSL_CTX_get_num_tickets\s*\(",
        ),
        "has_ssl_ctx_set_tmp_dh": (
            """
            #include <openssl/ssl.h>
            #include <openssl/dh.h>
            long test(SSL_CTX *ctx, DH *dh) { return SSL_CTX_set_tmp_dh(ctx, dh); }
            """,
            r"\bSSL_CTX_set_tmp_dh\s*\(",
        ),
        "has_x509_verify_param_get_hostflags": (
            """
            #include <openssl/x509.h>
            unsigned int test(const X509_VERIFY_PARAM *p) { return X509_VERIFY_PARAM_get_hostflags(p); }
            """,
            r"\bX509_VERIFY_PARAM_get_hostflags\s*\(",
        ),
        "has_ssl_read_write_ex": (
            """
            #include <openssl/ssl.h>
            int test(SSL *ssl, void *buf, size_t len, size_t *out) {
                return SSL_read_ex(ssl, buf, len, out) && SSL_write_ex(ssl, buf, len, out);
            }
            """,
            r"\bSSL_read_ex\s*\(",
        ),
        "has_x509_store_get1_objects": (
            """
            #include <openssl/x509.h>
            STACK_OF(X509_OBJECT) *test(X509_STORE *s) { return X509_STORE_get1_objects(s); }
            """,
            r"\bX509_STORE_get1_objects\s*\(",
        ),
        "has_psk_cb_typedefs": (
            """
            #include <openssl/ssl.h>
            SSL_psk_client_cb_func c_cb;
            SSL_psk_server_cb_func s_cb;
            """,
            r"\bSSL_psk_client_cb_func\b",
        ),
        "has_ssl_cipher_get_min_version": (
            """
            #include <openssl/ssl.h>
            uint16_t test(const SSL_CIPHER *c) { return SSL_CIPHER_get_min_version(c); }
            """,
            r"\bSSL_CIPHER_get_min_version\s*\(",
        ),
    }

    caps = {}
    for name, (snippet, fallback_regex) in probes.items():
        res = probe_c_snippet(compiler, include_dir, snippet)
        if res is None:
            if fallback_regex == "NO_HEADER_FALLBACK":
                res = False
            else:
                res = header_contains(include_dir, fallback_regex)
        caps[name] = res
    return caps


def read_boringssl_version_string(boringssl_dir):
    """Build a descriptive BoringSSL version string from BORINGSSL_METADATA.json / base.h."""
    bdir = Path(boringssl_dir)
    version = None
    api_version = None

    meta_path = bdir / "BORINGSSL_METADATA.json"
    if meta_path.is_file():
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            version = data.get("version") or None
            api_version = data.get("api_version") or None
        except Exception:
            pass

    if not api_version or api_version == "unknown":
        base_h = bdir / "include" / "openssl" / "base.h"
        if base_h.is_file():
            m = re.search(r"^#define\s+BORINGSSL_API_VERSION\s+(\d+)", base_h.read_text(encoding="utf-8", errors="ignore"), re.MULTILINE)
            if m:
                api_version = m.group(1)

    parts = ["BoringSSL"]
    if version:
        parts.append(str(version))
    if api_version and str(api_version) != "unknown":
        parts.append(f"(API v{api_version})")
    return " ".join(parts)


def generate_compat_header(caps, disable_tls1x=True, version_string="BoringSSL"):
    """Generate boringssl_compat.h dynamically from probed BoringSSL capabilities."""
    c_version_literal = json.dumps(version_string)
    lines = [
        "/* Auto-generated by patch_cpython.py for BoringSSL compatibility. */",
        "#ifndef PY_BORINGSSL_COMPAT_H",
        "#define PY_BORINGSSL_COMPAT_H",
        "",
        "#ifdef OPENSSL_IS_BORINGSSL",
        "",
        "/* BoringSSL is always thread-safe but does not define OPENSSL_THREADS. */",
        "#ifndef OPENSSL_THREADS",
        "#  define OPENSSL_THREADS 1",
        "#endif",
        "",
        "#ifdef OPENSSL_HEADER_CRYPTO_H",
        "/* Expose BoringSSL build commit, date, and API version via ssl.OPENSSL_VERSION. */",
        "static inline const char *_py_bssl_openssl_version(int which) {",
        "    if (which == OPENSSL_VERSION) {",
        f"        return {c_version_literal};",
        "    }",
        "    return OpenSSL_version(which);",
        "}",
        "#define OpenSSL_version(which) _py_bssl_openssl_version((which))",
        "#endif /* OPENSSL_HEADER_CRYPTO_H */",
        "",
        "#ifdef OPENSSL_HEADER_EVP_H",
        "/* BoringSSL puts EVP_MD_do_all() in libdecrepit.a rather than libcrypto.a.",
        " * Enumerate only real digests implemented in libcrypto.a and resolvable via",
        " * EVP_get_digestbyname() so _hashlib links cleanly without libdecrepit and",
        " * hashlib.algorithms_available contains only valid digests. */",
        "static inline void _py_bssl_evp_md_do_all(",
        "    void (*callback)(const EVP_MD *md, const char *from, const char *to, void *arg),",
        "    void *arg) {",
        "    const struct {",
        "        const EVP_MD *(*fn)(void);",
        "        const char *name;",
        "    } digests[] = {",
        "        { EVP_md5, \"md5\" },",
        "        { EVP_sha1, \"sha1\" },",
        "        { EVP_sha224, \"sha224\" },",
        "        { EVP_sha256, \"sha256\" },",
        "        { EVP_sha384, \"sha384\" },",
        "        { EVP_sha512, \"sha512\" },",
        "        { EVP_sha512_256, \"sha512-256\" },",
        "    };",
        "    for (size_t i = 0; i < sizeof(digests) / sizeof(digests[0]); i++) {",
        "        const EVP_MD *md = digests[i].fn();",
        "        if (md != NULL && EVP_get_digestbyname(digests[i].name) != NULL) {",
        "            callback(md, digests[i].name, NULL, arg);",
        "        }",
        "    }",
        "}",
        "#define EVP_MD_do_all(cb, arg) _py_bssl_evp_md_do_all((cb), (arg))",
        "#endif /* OPENSSL_HEADER_EVP_H */",
        "",
    ]

    if disable_tls1x:
        lines.extend([
            "/* Hardening: disable SSLv3, TLS 1.0, and TLS 1.1 at the CPython layer without patching BoringSSL. */",
            "#ifndef OPENSSL_NO_SSL3",
            "#  define OPENSSL_NO_SSL3 1",
            "#endif",
            "#ifndef OPENSSL_NO_SSL3_METHOD",
            "#  define OPENSSL_NO_SSL3_METHOD 1",
            "#endif",
            "#ifndef OPENSSL_NO_TLS1",
            "#  define OPENSSL_NO_TLS1 1",
            "#endif",
            "#ifndef OPENSSL_NO_TLS1_METHOD",
            "#  define OPENSSL_NO_TLS1_METHOD 1",
            "#endif",
            "#ifndef OPENSSL_NO_TLS1_1",
            "#  define OPENSSL_NO_TLS1_1 1",
            "#endif",
            "#ifndef OPENSSL_NO_TLS1_1_METHOD",
            "#  define OPENSSL_NO_TLS1_1_METHOD 1",
            "#endif",
            "",
        ])

    lines.extend([
        "/* Only emit SSL/TLS shims when <openssl/ssl.h> has been included (e.g., Modules/_ssl.c). */",
        "#ifdef OPENSSL_HEADER_SSL_H",
        "",
        "/* Option/mode compatibility macros (no-ops if omitted by BoringSSL). */",
        "#ifndef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS",
        "#  define SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS 0",
        "#endif",
        "#ifndef SSL_OP_NO_SSLv2",
        "#  define SSL_OP_NO_SSLv2 0",
        "#endif",
        "#ifndef SSL_OP_NO_SSLv3",
        "#  define SSL_OP_NO_SSLv3 0",
        "#endif",
        "#ifndef SSL_OP_SINGLE_DH_USE",
        "#  define SSL_OP_SINGLE_DH_USE 0",
        "#endif",
        "#ifndef SSL_MODE_AUTO_RETRY",
        "#  define SSL_MODE_AUTO_RETRY 0",
        "#endif",
        "#ifndef SSL_MODE_RELEASE_BUFFERS",
        "#  define SSL_MODE_RELEASE_BUFFERS 0",
        "#endif",
        "",
    ])

    if disable_tls1x:
        lines.extend([
            "/* Enforce TLS 1.2+ floor even if Python code sets context.minimum_version / maximum_version. */",
            "static inline int _py_bssl_ctx_set_min_proto_version(SSL_CTX *ctx, uint16_t version) {",
            "    if (version != 0 && version < TLS1_2_VERSION) {",
            "        return 0;",
            "    }",
            "    return SSL_CTX_set_min_proto_version(ctx, version);",
            "}",
            "static inline int _py_bssl_ctx_set_max_proto_version(SSL_CTX *ctx, uint16_t version) {",
            "    if (version != 0 && version < TLS1_2_VERSION) {",
            "        return 0;",
            "    }",
            "    return SSL_CTX_set_max_proto_version(ctx, version);",
            "}",
            "#define SSL_CTX_set_min_proto_version(ctx, ver) _py_bssl_ctx_set_min_proto_version((ctx), (ver))",
            "#define SSL_CTX_set_max_proto_version(ctx, ver) _py_bssl_ctx_set_max_proto_version((ctx), (ver))",
            "",
        ])

    if not caps["has_set_ciphersuites"]:
        lines.extend([
            "/* BoringSSL manages TLS 1.3 cipher suites automatically. */",
            "static inline int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str) {",
            "    (void)ctx; (void)str;",
            "    return 0;",
            "}",
            "",
        ])

    if not caps["has_get_security_level"]:
        lines.extend([
            "/* BoringSSL enforces modern minimums natively without OpenSSL security levels. */",
            "static inline int SSL_CTX_get_security_level(const SSL_CTX *ctx) {",
            "    (void)ctx;",
            "    return 2;",
            "}",
            "",
        ])

    if not caps["has_get0_verified_chain"]:
        lines.extend([
            "/* Map verified chain lookup onto BoringSSL's peer full cert chain when verified. */",
            "static inline STACK_OF(X509) *SSL_get0_verified_chain(const SSL *ssl) {",
            "    if (SSL_get_verify_result(ssl) != X509_V_OK) {",
            "        return NULL;",
            "    }",
            "    return SSL_get_peer_full_cert_chain(ssl);",
            "}",
            "",
        ])

    if not caps["has_get_client_ciphers"]:
        lines.extend([
            "/* BoringSSL does not expose raw client cipher stack for server shared_ciphers(). */",
            "static inline STACK_OF(SSL_CIPHER) *SSL_get_client_ciphers(const SSL *ssl) {",
            "    (void)ssl;",
            "    return NULL;",
            "}",
            "",
        ])

    if not caps["has_2arg_sk_ssl_cipher_find"]:
        lines.extend([
            "/* BoringSSL's sk_SSL_CIPHER_find takes an extra size_t *out_index argument. */",
            "static inline int _py_bssl_sk_SSL_CIPHER_find(const STACK_OF(SSL_CIPHER) *sk, const SSL_CIPHER *c) {",
            "    size_t idx = 0;",
            "    if (sk == NULL) {",
            "        return -1;",
            "    }",
            "    return sk_SSL_CIPHER_find(sk, &idx, c) ? (int)idx : -1;",
            "}",
            "#define sk_SSL_CIPHER_find(sk, c) _py_bssl_sk_SSL_CIPHER_find((sk), (c))",
            "",
        ])

    if not caps["has_set1_sigalgs_list"]:
        lines.extend([
            "static inline int SSL_CTX_set1_sigalgs_list(SSL_CTX *ctx, const char *str) {",
            "    (void)ctx; (void)str;",
            "    return 0;",
            "}",
            "",
        ])

    if not caps["has_set1_client_sigalgs_list"]:
        lines.extend([
            "static inline int SSL_CTX_set1_client_sigalgs_list(SSL_CTX *ctx, const char *str) {",
            "    (void)ctx; (void)str;",
            "    return 0;",
            "}",
            "",
        ])

    if not caps["has_ssl_ctx_get_num_tickets"]:
        lines.extend([
            "static inline size_t SSL_CTX_get_num_tickets(const SSL_CTX *ctx) {",
            "    (void)ctx;",
            "    return 2;",
            "}",
            "",
        ])

    if not caps["has_ssl_ctx_set_num_tickets"]:
        lines.extend([
            "static inline int SSL_CTX_set_num_tickets(SSL_CTX *ctx, size_t num_tickets) {",
            "    (void)ctx; (void)num_tickets;",
            "    return 1;",
            "}",
            "",
        ])

    if not caps["has_x509_verify_param_get_hostflags"]:
        lines.extend([
            "/* BoringSSL keeps X509_VERIFY_PARAM hostflags opaque; return CPython's strict default. */",
            "static inline unsigned int X509_VERIFY_PARAM_get_hostflags(const X509_VERIFY_PARAM *param) {",
            "    (void)param;",
            "    return X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;",
            "}",
            "",
        ])

    if not caps["has_ssl_read_write_ex"]:
        lines.extend([
            "/* Emulate OpenSSL 1.1.1 SSL_read_ex / SSL_write_ex with proper WANT_READ/WANT_WRITE handling. */",
            "#include <limits.h>",
            "static inline int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes) {",
            "    if (num == 0) {",
            "        if (readbytes) *readbytes = 0;",
            "        return 1;",
            "    }",
            "    int chunk = (num > (size_t)INT_MAX) ? INT_MAX : (int)num;",
            "    int r = SSL_read(ssl, buf, chunk);",
            "    if (r > 0) {",
            "        if (readbytes) *readbytes = (size_t)r;",
            "        return 1;",
            "    }",
            "    if (readbytes) *readbytes = 0;",
            "    return 0;",
            "}",
            "static inline int SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written) {",
            "    if (num == 0) {",
            "        if (written) *written = 0;",
            "        return 1;",
            "    }",
            "    int chunk = (num > (size_t)INT_MAX) ? INT_MAX : (int)num;",
            "    int r = SSL_write(ssl, buf, chunk);",
            "    if (r > 0) {",
            "        if (written) *written = (size_t)r;",
            "        return 1;",
            "    }",
            "    if (written) *written = 0;",
            "    return 0;",
            "}",
            "/* Ensure SSL_get_error(ssl, 0) from SSL_{read,write}_ex preserves WANT_READ / WANT_WRITE. */",
            "static inline int _py_bssl_get_error(const SSL *ssl, int ret_code) {",
            "    if (ret_code == 0 && SSL_want(ssl) != SSL_NOTHING) {",
            "        return SSL_get_error(ssl, -1);",
            "    }",
            "    return SSL_get_error(ssl, ret_code);",
            "}",
            "#define SSL_get_error(ssl, ret) _py_bssl_get_error((ssl), (ret))",
            "",
        ])

    if not caps["has_psk_cb_typedefs"]:
        lines.extend([
            "/* BoringSSL exposes PSK callbacks without the OpenSSL typedef aliases. */",
            "typedef unsigned int (*SSL_psk_client_cb_func)(",
            "    SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len,",
            "    unsigned char *psk, unsigned int max_psk_len);",
            "typedef unsigned int (*SSL_psk_server_cb_func)(",
            "    SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len);",
            "",
        ])

    if caps.get("has_ssl_cipher_get_min_version"):
        lines.extend([
            "/* BoringSSL hardcodes SSL_CIPHER_get_version() to \"TLSv1/SSLv3\"; derive it from",
            " * SSL_CIPHER_get_min_version() so sock.cipher()[1] matches OpenSSL (e.g. TLSv1.3). */",
            "static inline const char *_py_bssl_ssl_cipher_get_version(const SSL_CIPHER *cipher) {",
            "    if (cipher == NULL) {",
            "        return \"(NONE)\";",
            "    }",
            "    uint16_t min_ver = SSL_CIPHER_get_min_version(cipher);",
            "    if (min_ver >= TLS1_3_VERSION) {",
            "        return \"TLSv1.3\";",
            "    }",
            "    if (min_ver >= TLS1_2_VERSION) {",
            "        return \"TLSv1.2\";",
            "    }",
            "    return \"TLSv1/SSLv3\";",
            "}",
            "#define SSL_CIPHER_get_version(cipher) _py_bssl_ssl_cipher_get_version((cipher))",
            "",
        ])

    lines.extend([
        "#endif /* OPENSSL_HEADER_SSL_H */",
        "#endif /* OPENSSL_IS_BORINGSSL */",
        "#endif /* PY_BORINGSSL_COMPAT_H */",
        "",
    ])
    return "\n".join(lines)


def patch_boringssl_win32_headers(boringssl_dir):
    """
    On Windows, <wincrypt.h> (included by Modules/_ssl.c beforeModules/_ssl.h -> <openssl/evp.h>)
    defines macros like X509_NAME, X509_EXTENSIONS, PKCS7_SIGNER_INFO, and OCSP_REQUEST.
    OpenSSL's <openssl/types.h> #undefs these, whereas BoringSSL's <openssl/base.h> does not.
    Inject the #undef guard into the installed <openssl/base.h>.
    """
    base_h = Path(boringssl_dir) / "include" / "openssl" / "base.h"
    if not base_h.is_file():
        return
    text = base_h.read_text(encoding="utf-8")
    marker = "/* PY_BORINGSSL_WINCRYPT_UNDEF */"
    if marker in text:
        print("  [skip] openssl/base.h already has Windows wincrypt.h #undef guard")
        return

    undef_block = (
        f"\n{marker}\n"
        "#if defined(_WIN32) || defined(MS_WINDOWS)\n"
        "#  undef X509_NAME\n"
        "#  undef X509_EXTENSIONS\n"
        "#  undef X509_CERT_PAIR\n"
        "#  undef PKCS7_ISSUER_AND_SERIAL\n"
        "#  undef PKCS7_SIGNER_INFO\n"
        "#  undef OCSP_REQUEST\n"
        "#  undef OCSP_RESPONSE\n"
        "#endif\n"
    )
    anchor = re.search(r"(#define\s+OPENSSL_HEADER_BASE_H\b[^\n]*\n)", text)
    if anchor:
        idx = anchor.end()
        new_text = text[:idx] + undef_block + text[idx:]
    else:
        new_text = undef_block + text

    base_h.write_text(new_text, encoding="utf-8")
    print("  [patched] openssl/base.h: injected Windows wincrypt.h macro #undef guard")


def inject_compat_include(filepath):
    """Semantically insert `#include "boringssl_compat.h"` right before `#ifndef OPENSSL_THREADS`."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"Expected CPython source file not found: {path}")
    text = path.read_text(encoding="utf-8")
    marker = '#include "boringssl_compat.h"'
    if marker in text:
        print(f"  [skip] {path.name} already includes boringssl_compat.h")
        return False

    anchor = re.search(r"^[ \t]*#[ \t]*ifndef[ \t]+OPENSSL_THREADS\b", text, re.MULTILINE)
    if anchor:
        idx = anchor.start()
        new_text = text[:idx] + f"{marker}\n\n" + text[idx:]
    else:
        # Fallback: insert right after the last openssl/*.h include line
        matches = list(re.finditer(r'^[ \t]*#[ \t]*include[ \t]+[<"]openssl/[^>"]+[>"][^\n]*\n', text, re.MULTILINE))
        if not matches:
            raise RuntimeError(f"Could not find anchor in {path} to inject boringssl_compat.h")
        idx = matches[-1].end()
        new_text = text[:idx] + f"\n{marker}\n" + text[idx:]

    path.write_text(new_text, encoding="utf-8")
    print(f"  [patched] {path.name}: injected boringssl_compat.h")
    return True


def probe_cxx_runtime_lib(compiler, boringssl_dir):
    """
    Detect whether linking C code against static BoringSSL (libssl.a + libcrypto.a)
    requires an explicit C++ runtime library (-lc++ on macOS, -lstdc++ on Linux).
    Returns "" (none needed), "-lc++", or "-lstdc++".
    """
    if not compiler or os.name == "nt":
        return ""
    compiler_base = os.path.basename(compiler).lower()
    if compiler_base in ("cl", "cl.exe", "clang-cl", "clang-cl.exe"):
        return ""

    include_dir = Path(boringssl_dir) / "include"
    lib_dir = Path(boringssl_dir) / "lib"
    snippet = """
    #include <openssl/ssl.h>
    #include <openssl/evp.h>
    int main(void) {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (ctx) SSL_CTX_free(ctx);
        EVP_MD_CTX *m = EVP_MD_CTX_new();
        if (m) EVP_MD_CTX_free(m);
        return 0;
    }
    """
    candidates = ["", "-lc++", "-lstdc++"] if sys.platform == "darwin" else ["", "-lstdc++", "-lc++"]
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "link_probe.c"
        out = Path(tmpdir) / "link_probe"
        src.write_text(snippet, encoding="utf-8")
        for flag in candidates:
            cmd = [
                compiler,
                f"-I{include_dir}",
                str(src),
                f"-L{lib_dir}",
                "-lssl",
                "-lcrypto",
            ]
            if flag:
                cmd.append(flag)
            if sys.platform.startswith("linux"):
                cmd.append("-lpthread")
            cmd.extend(["-o", str(out)])
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if proc.returncode == 0:
                return flag
    return "-lc++" if sys.platform == "darwin" else "-lstdc++"


def patch_hashopenssl_xof(cpython_dir):
    """
    Guard unguarded `state->HASHXOF_type` reference in Modules/_hashopenssl.c when
    PY_OPENSSL_HAS_SHAKE is not defined (e.g. BoringSSL omits SHAKE NIDs).
    """
    hash_c = Path(cpython_dir) / "Modules" / "_hashopenssl.c"
    if not hash_c.is_file():
        return
    text = hash_c.read_text(encoding="utf-8")
    if "#ifdef PY_OPENSSL_HAS_SHAKE\n    type = PY_EVP_MD_xof(digest)" in text:
        print("  [skip] _hashopenssl.c: HASHXOF_type already guarded")
        return

    pattern = r"^([ \t]*)(type\s*=\s*PY_EVP_MD_xof\(digest\)\s*\?\s*state->HASHXOF_type\s*:\s*state->HASH_type;)[ \t]*$"
    replacement = (
        r"#ifdef PY_OPENSSL_HAS_SHAKE\n"
        r"\1\2\n"
        r"#else\n"
        r"\1type = state->HASH_type;\n"
        r"#endif"
    )
    new_text, count = re.subn(pattern, replacement, text, flags=re.MULTILINE)
    if count:
        hash_c.write_text(new_text, encoding="utf-8")
        print(f"  [patched] _hashopenssl.c: guarded HASHXOF_type with #ifdef PY_OPENSSL_HAS_SHAKE ({count} occurrence(s))")
    else:
        print("  [skip] _hashopenssl.c: unguarded HASHXOF_type pattern not present")


def patch_ssl_x509_store_backport(cpython_dir, has_x509_store_get1_objects):
    """
    CPython defines a static polyfill for X509_STORE_get1_objects() when
    OPENSSL_VERSION_NUMBER < 0x30300000L && !defined(LIBRESSL_VERSION_NUMBER).
    BoringSSL already provides X509_STORE_get1_objects() natively (and reports
    OPENSSL_VERSION_NUMBER == 0x1010107f), so exclude OPENSSL_IS_BORINGSSL.
    """
    if not has_x509_store_get1_objects:
        return
    ssl_c = Path(cpython_dir) / "Modules" / "_ssl.c"
    if not ssl_c.is_file():
        return
    text = ssl_c.read_text(encoding="utf-8")
    if "!defined(OPENSSL_IS_BORINGSSL)" in text:
        print("  [skip] _ssl.c: X509_STORE_get1_objects backport already guarded for BoringSSL")
        return

    pattern = (
        r"(#if\s+OPENSSL_VERSION_NUMBER\s*<\s*0x30300000L\s*&&\s*!defined\(LIBRESSL_VERSION_NUMBER\))"
        r"(?=[\s\S]{0,1200}X509_STORE_get1_objects)"
    )
    new_text, count = re.subn(pattern, r"\1 && !defined(OPENSSL_IS_BORINGSSL)", text, count=1)
    if count:
        ssl_c.write_text(new_text, encoding="utf-8")
        print("  [patched] _ssl.c: guarded X509_STORE_get1_objects backport for BoringSSL")
    else:
        print("  [skip] _ssl.c: X509_STORE_get1_objects backport pattern not present")


def patch_configure_hashlib_check(cpython_dir, has_sha3_512_nid, cxx_lib="", static_exclude_libs=False):
    """
    1. Remove NID_sha3_512 requirement from configure's hashlib link probe when BoringSSL lacks it.
    2. Add <openssl/objects.h> to configure's hashlib probe (BoringSSL's evp.h omits it).
    3. Configure OPENSSL_LIBS in configure with required C++ runtime (-lc++ / -lstdc++)
       and optional GNU ld --exclude-libs static hiding on Linux.
    """
    for fname in ("configure", "configure.ac"):
        fpath = Path(cpython_dir) / fname
        if not fpath.is_file():
            continue
        text = fpath.read_text(encoding="utf-8")
        modified = False

        if not has_sha3_512_nid:
            pattern = r"^[ \t]*OBJ_nid2sn\(NID_sha3_512\);[ \t]*\r?\n"
            new_text, count = re.subn(pattern, "", text, flags=re.MULTILINE)
            if count:
                text = new_text
                modified = True
                print(f"  [patched] {fname}: removed NID_sha3_512 from hashlib probe ({count} occurrence(s))")

        # BoringSSL's <openssl/evp.h> does not transitively include <openssl/objects.h>
        # (where OBJ_nid2sn is declared), so add it to configure's hashlib link probe.
        probe_anchor = re.compile(
            r"(#include\s+<openssl/evp\.h>\r?\n)(?![ \t]*#include\s+<openssl/objects\.h>)"
            r"(?=[\s\S]{0,400}OBJ_nid2sn\s*\(\s*NID_md5\s*\))"
        )
        new_text, count = probe_anchor.subn(r"\1      #include <openssl/objects.h>\n", text)
        if count:
            text = new_text
            modified = True
            print(f"  [patched] {fname}: added <openssl/objects.h> to hashlib probe ({count} occurrence(s))")

        if fname == "configure" and (cxx_lib or static_exclude_libs):
            old_line = 'OPENSSL_LIBS="-lssl -lcrypto"'
            extra = f" {cxx_lib}" if cxx_lib else ""
            if static_exclude_libs:
                new_line = (
                    'OPENSSL_LIBS="-l:libssl.a -Wl,--exclude-libs,libssl.a '
                    f'-l:libcrypto.a -Wl,--exclude-libs,libcrypto.a{extra}"'
                )
            else:
                new_line = f'OPENSSL_LIBS="-lssl -lcrypto{extra}"'
            if old_line in text:
                text = text.replace(old_line, new_line)
                modified = True
                print(f"  [patched] {fname}: set {new_line}")
            elif new_line in text:
                print(f"  [skip] {fname}: OPENSSL_LIBS already configured")

        if modified:
            fpath.write_text(text, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Dynamically patch CPython for BoringSSL HEAD.")
    parser.add_argument("--boringssl-dir", required=True, help="Installed BoringSSL root directory")
    parser.add_argument("--cpython-dir", required=True, help="Checked-out CPython source directory")
    parser.add_argument("--output-header", help="Output path for boringssl_compat.h (default: <boringssl-dir>/include/boringssl_compat.h)")
    parser.add_argument("--compiler", default=None, help="C compiler for feature probing (auto-detected if omitted)")
    parser.add_argument("--allow-tls1x", action="store_true", help="Do not enforce TLS 1.2+ floor in boringssl_compat.h")
    parser.add_argument("--static-exclude-libs", action="store_true", help="Patch Modules/Setup with GNU ld --exclude-libs (Linux)")
    args = parser.parse_args()

    compiler = detect_compiler(args.compiler)
    print(f"Probing BoringSSL installation at: {args.boringssl_dir}")
    print(f"Using C compiler probe: {compiler or 'None (header-scan fallback)'}")

    patch_boringssl_win32_headers(args.boringssl_dir)
    caps = probe_capabilities(args.boringssl_dir, compiler=compiler)
    print("Detected BoringSSL capabilities:")
    for k, v in sorted(caps.items()):
        status = "PRESENT" if v else "MISSING (will shim)"
        print(f"  - {k}: {status}")

    version_string = read_boringssl_version_string(args.boringssl_dir)
    print(f"Resolved BoringSSL Python version string: {version_string}")

    header_path = Path(args.output_header) if args.output_header else (Path(args.boringssl_dir) / "include" / "boringssl_compat.h")
    header_path.parent.mkdir(parents=True, exist_ok=True)
    header_content = generate_compat_header(caps, disable_tls1x=not args.allow_tls1x, version_string=version_string)
    header_path.write_text(header_content, encoding="utf-8")
    print(f"Generated compatibility header: {header_path}")

    cxx_lib = probe_cxx_runtime_lib(compiler, args.boringssl_dir)
    print(f"Detected C++ runtime requirement for static BoringSSL: {cxx_lib or 'none'}")

    print(f"Applying semantic patches to CPython at: {args.cpython_dir}")
    inject_compat_include(Path(args.cpython_dir) / "Modules" / "_ssl.c")
    inject_compat_include(Path(args.cpython_dir) / "Modules" / "_hashopenssl.c")
    patch_hashopenssl_xof(args.cpython_dir)
    patch_ssl_x509_store_backport(args.cpython_dir, caps["has_x509_store_get1_objects"])
    patch_configure_hashlib_check(
        args.cpython_dir,
        caps["has_sha3_512_nid"],
        cxx_lib=cxx_lib,
        static_exclude_libs=args.static_exclude_libs,
    )

    print("CPython BoringSSL adaptation completed successfully.")


if __name__ == "__main__":
    main()
