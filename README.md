# python-boringssl-latest

A reusable GitHub Action and automated weekly build pipeline that compiles and distributes the latest stable version of **Python** statically linked against **Google BoringSSL HEAD** across all currently supported GitHub-hosted runners (**Linux**, **macOS**, and **Windows**, across both **x64** and **arm64** architectures).

Modeled directly on [python-openssl-latest](https://github.com/jay0lee/python-openssl-latest) for [GAM](https://github.com/gam-team/gam) and [GYB](https://github.com/gam-team/got-your-back), targeting Google's own TLS stack instead of OpenSSL.

---

## Features

- **BoringSSL HEAD ("Live at Head")**: Tracks `google/boringssl` `main` HEAD automatically each week, resolving the exact commit SHA once in the discovery job so all matrix runners build the identical BoringSSL revision.
- **Dynamic, Diff-Free CPython Adaptation (`scripts/patch_cpython.py`)**:
  - Probes the freshly compiled BoringSSL headers and static libraries (`libssl.a` / `libcrypto.a`) with the local C compiler.
  - Dynamically generates `boringssl_compat.h` containing **only** shims for OpenSSL APIs absent in that exact BoringSSL revision—automatically adapting as BoringSSL HEAD or new CPython releases evolve.
  - Enforces a **TLS 1.2+ floor** at the CPython compatibility layer (`OPENSSL_NO_SSL3`, `OPENSSL_NO_TLS1`, `OPENSSL_NO_TLS1_1`, plus `min_proto_version` clamping) without patching BoringSSL's source code.
  - Uses CPython's built-in HACL* implementations for SHA-3 and BLAKE2 (`--with-builtin-hashlib-hashes=sha3,blake2`) alongside BoringSSL's EVP engine for SHA-1/2, MD5, HMAC, PBKDF2, and scrypt.
- **Dynamic Runner Discovery & Brownout Protection**: Automatically discovers free-tier GitHub Actions runners from `actions/runner-images` and drops deprecated runners 1 day before brownouts begin.
- **GAM/GYB Runtime Validation (`scripts/validate_runtime.py`)**: Verifies BoringSSL identity, TLS 1.0/1.1 disablement, TLS 1.3 handshake to `https://www.googleapis.com`, full `hashlib` coverage (BoringSSL + HACL*), SQLite WAL concurrency, multiprocessing, compression, JSON C accelerator, and native binary architecture.

---

## Usage in Consuming Workflows (GAM, GYB, etc.)

```yaml
jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-24.04, ubuntu-24.04-arm, macos-15, macos-15-intel, windows-latest, windows-11-arm]
    steps:
      - uses: actions/checkout@v4

      - name: Set up latest Python + BoringSSL
        uses: jay0lee/python-boringssl-latest@v1

      - name: Verify Environment
        run: |
          python -VV
          python -c "import ssl; print(f'SSL Library: {ssl.OPENSSL_VERSION}')"
```

### Action Inputs

| Input | Description | Default |
| :--- | :--- | :--- |
| `version` | Target release tag (e.g. `v1.2026.11.20.0400`) or `latest` | Defaults to action ref if pinned, else `latest` |
| `install-dir` | Custom installation directory | `$RUNNER_TOOL_CACHE/python-boringssl-bundle` |
| `set-env` | Export `PATH`, `PYTHON`, `BORINGSSL_INSTALL_PATH`, `OPENSSL_INSTALL_PATH`, `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH` | `true` |
| `quiet` | Suppress printing build configuration summary | `false` |
| `github-token` | GitHub token for querying releases and downloading assets | `${{ github.token }}` |

### Action Outputs

| Output | Description |
| :--- | :--- |
| `python-path` | Absolute path to the installed `python` / `python3` executable |
| `python-version` | Version of the installed Python runtime |
| `boringssl-path` | Root directory of the installed BoringSSL headers, static libs, and `bssl` CLI |
| `boringssl-version` | Resolved BoringSSL commit version (`YYYYMMDD-<short_sha>`) |
| `build-summary` | Text summary of build configuration and compiler flags |

---

## Local Development and Testing

Run the unit test suite:
```bash
python3 -m unittest discover -s tests -v
```

Test dynamic matrix and BoringSSL HEAD discovery:
```bash
python3 scripts/discover_matrix.py --output-json
```

Local macOS/Linux build test:
```bash
./scripts/build_boringssl.sh main /tmp/bssl-src /tmp/bssl-install
./scripts/build_python.sh 3.15.2 local-head /tmp/bssl-install /tmp/py-src /tmp/py-install
/tmp/py-install/bin/python3 scripts/validate_runtime.py
```

---

## Repository Structure

```
├── .github/
│   └── workflows/
│       ├── build-and-release.yml   # Weekly matrix build and release workflow
│       └── test-action.yml         # Unit tests, dry-run discovery, and E2E action tests
├── action.yml                      # Reusable GitHub Action definition
├── patches/
│   └── windows/
│       └── boringssl.props         # MSBuild ExternalProps for static BoringSSL linking
├── scripts/
│   ├── discover_matrix.py          # Dynamic runner matrix, Python tag, and BoringSSL HEAD discovery
│   ├── build_boringssl.sh          # Unix BoringSSL CMake/Ninja build script
│   ├── build_boringssl.ps1         # Windows BoringSSL CMake/Ninja+MSVC build script
│   ├── patch_cpython.py            # Dynamic BoringSSL capability prober & CPython adapter
│   ├── build_python.sh             # Unix CPython build script
│   ├── build_python.ps1            # Windows CPython build script
│   ├── setup_msvc.ps1              # Native MSVC environment activation (Windows)
│   ├── validate_runtime.py         # GAM/GYB runtime & TLS hardening validation suite
│   ├── build_info.py               # Build metadata collector & summary formatter
│   └── install.py                  # Client installer called by action.yml
├── tests/
│   ├── test_discover_matrix.py
│   ├── test_patch_cpython.py
│   └── test_build_info.py
├── LICENSE
└── README.md
```

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
