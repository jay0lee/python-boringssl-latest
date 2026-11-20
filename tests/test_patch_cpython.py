#!/usr/bin/env python3
"""Unit tests for dynamic BoringSSL compatibility patching (patch_cpython.py)."""

import shutil
import tempfile
import unittest
from pathlib import Path

from scripts.patch_cpython import (
    generate_compat_header,
    inject_compat_include,
    patch_boringssl_win32_headers,
    patch_configure_hashlib_check,
    patch_hashopenssl_xof,
    patch_ssl_x509_store_backport,
)


class TestPatchCPython(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_generate_compat_header_skips_present_apis(self):
        all_present = {
            "has_set_ciphersuites": True,
            "has_get_security_level": True,
            "has_get0_verified_chain": True,
            "has_get_client_ciphers": True,
            "has_2arg_sk_ssl_cipher_find": True,
            "has_set1_sigalgs_list": True,
            "has_set1_client_sigalgs_list": True,
            "has_sha3_512_nid": True,
            "has_ssl_ctx_set_num_tickets": True,
            "has_ssl_ctx_get_num_tickets": True,
            "has_ssl_ctx_set_tmp_dh": True,
            "has_x509_verify_param_get_hostflags": True,
            "has_ssl_read_write_ex": True,
            "has_x509_store_get1_objects": True,
            "has_psk_cb_typedefs": True,
        }
        hdr = generate_compat_header(all_present, disable_tls1x=True)
        self.assertIn("OPENSSL_NO_TLS1", hdr)
        self.assertIn("_py_bssl_ctx_set_min_proto_version", hdr)
        self.assertIn("_py_bssl_evp_md_do_all", hdr)
        self.assertNotIn("SSL_CTX_set_ciphersuites(", hdr)
        self.assertNotIn("SSL_read_ex(", hdr)
        self.assertNotIn("SSL_psk_client_cb_func", hdr)

    def test_generate_compat_header_emits_missing_shims(self):
        all_missing = {k: False for k in [
            "has_set_ciphersuites", "has_get_security_level", "has_get0_verified_chain",
            "has_get_client_ciphers", "has_2arg_sk_ssl_cipher_find", "has_set1_sigalgs_list",
            "has_set1_client_sigalgs_list", "has_sha3_512_nid", "has_ssl_ctx_set_num_tickets",
            "has_ssl_ctx_get_num_tickets", "has_ssl_ctx_set_tmp_dh",
            "has_x509_verify_param_get_hostflags", "has_ssl_read_write_ex",
            "has_x509_store_get1_objects", "has_psk_cb_typedefs",
        ]}
        hdr = generate_compat_header(all_missing, disable_tls1x=True)
        self.assertIn("SSL_CTX_set_ciphersuites(", hdr)
        self.assertIn("SSL_read_ex(", hdr)
        self.assertIn("_py_bssl_get_error(", hdr)
        self.assertIn("SSL_psk_client_cb_func", hdr)
        self.assertIn("X509_VERIFY_PARAM_get_hostflags(", hdr)

    def test_semantic_patchers_are_idempotent(self):
        modules = self.tmp / "Modules"
        modules.mkdir()
        ssl_c = modules / "_ssl.c"
        ssl_c.write_text(
            '#include "openssl/ssl.h"\n'
            '#ifndef OPENSSL_THREADS\n'
            '#  error "no threads"\n'
            '#endif\n'
            '#if OPENSSL_VERSION_NUMBER < 0x30300000L && !defined(LIBRESSL_VERSION_NUMBER)\n'
            'static STACK_OF(X509_OBJECT) *X509_STORE_get1_objects(X509_STORE *s) { return NULL; }\n'
            '#endif\n',
            encoding="utf-8",
        )
        hash_c = modules / "_hashopenssl.c"
        hash_c.write_text(
            '#include <openssl/evp.h>\n'
            '#ifndef OPENSSL_THREADS\n'
            '#  error "no threads"\n'
            '#endif\n'
            '    type = PY_EVP_MD_xof(digest) ? state->HASHXOF_type : state->HASH_type;\n',
            encoding="utf-8",
        )
        configure = self.tmp / "configure"
        configure.write_text(
            'OPENSSL_LIBS="-lssl -lcrypto"\n'
            '#include <openssl/opensslv.h>\n'
            '#include <openssl/evp.h>\n'
            'OBJ_nid2sn(NID_md5);\n'
            'OBJ_nid2sn(NID_sha3_512);\n',
            encoding="utf-8",
        )

        # Run twice to guarantee idempotency
        for _ in range(2):
            inject_compat_include(ssl_c)
            inject_compat_include(hash_c)
            patch_hashopenssl_xof(self.tmp)
            patch_ssl_x509_store_backport(self.tmp, has_x509_store_get1_objects=True)
            patch_configure_hashlib_check(self.tmp, has_sha3_512_nid=False, cxx_lib="-lc++")

        self.assertEqual(ssl_c.read_text().count('#include "boringssl_compat.h"'), 1)
        self.assertEqual(ssl_c.read_text().count("!defined(OPENSSL_IS_BORINGSSL)"), 1)
        self.assertEqual(hash_c.read_text().count("#ifdef PY_OPENSSL_HAS_SHAKE"), 1)
        conf_out = configure.read_text()
        self.assertNotIn("NID_sha3_512", conf_out)
        self.assertEqual(conf_out.count("#include <openssl/objects.h>"), 1)
        self.assertIn('OPENSSL_LIBS="-lssl -lcrypto -lc++"', conf_out)

        bssl_inc = self.tmp / "include" / "openssl"
        bssl_inc.mkdir(parents=True)
        base_h = bssl_inc / "base.h"
        base_h.write_text("#ifndef OPENSSL_HEADER_BASE_H\n#define OPENSSL_HEADER_BASE_H\ntypedef struct X509_name_st X509_NAME;\n#endif\n", encoding="utf-8")
        for _ in range(2):
            patch_boringssl_win32_headers(self.tmp)
        self.assertEqual(base_h.read_text().count("undef X509_NAME"), 1)


if __name__ == "__main__":
    unittest.main()
