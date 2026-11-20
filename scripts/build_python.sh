#!/usr/bin/env bash
set -euo pipefail

# build_python.sh - Builds CPython statically linked against BoringSSL matching GAM specifications
# Usage: ./scripts/build_python.sh <python_version> <boringssl_version> <boringssl_install_dir> <python_source_dir> <python_install_dir>

PYTHON_VERSION="${1:-}"
BORINGSSL_VERSION="${2:-}"
BORINGSSL_INSTALL_DIR="${3:-}"
SOURCE_DIR="${4:-}"
INSTALL_DIR="${5:-}"

if [[ -z "$PYTHON_VERSION" || -z "$BORINGSSL_VERSION" || -z "$BORINGSSL_INSTALL_DIR" || -z "$SOURCE_DIR" || -z "$INSTALL_DIR" ]]; then
  echo "Usage: $0 <python_version> <boringssl_version> <boringssl_install_dir> <source_dir> <install_dir>" >&2
  exit 1
fi

echo "=================================================="
echo "Building Python ${PYTHON_VERSION} with BoringSSL ${BORINGSSL_VERSION}"
echo "BoringSSL Install: ${BORINGSSL_INSTALL_DIR}"
echo "Python Source:     ${SOURCE_DIR}"
echo "Python Install:    ${INSTALL_DIR}"
echo "=================================================="

RUNNER_OS="${RUNNER_OS:-$(uname -s)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

mkdir -p "$SOURCE_DIR" "$INSTALL_DIR"

if [[ ! -f "${SOURCE_DIR}/configure" ]]; then
  echo "Cloning CPython source..."
  git clone --depth 1 --branch "v${PYTHON_VERSION}" https://github.com/python/cpython.git "$SOURCE_DIR" \
    || {
      git clone --filter=blob:none https://github.com/python/cpython.git "$SOURCE_DIR"
      cd "$SOURCE_DIR"
      git checkout "${PYTHON_VERSION}"
    }
fi
cd "$SOURCE_DIR"

# Dynamically probe BoringSSL HEAD and patch CPython
PATCH_ARGS=(
  --boringssl-dir "${BORINGSSL_INSTALL_DIR}"
  --cpython-dir "${SOURCE_DIR}"
)
if [[ "$RUNNER_OS" == "Linux" ]]; then
  PATCH_ARGS+=(--static-exclude-libs)
fi
python3 "${SCRIPT_DIR}/patch_cpython.py" "${PATCH_ARGS[@]}"

# Detect parallel jobs
if command -v nproc >/dev/null 2>&1; then
  JOBS="$(nproc)"
elif command -v sysctl >/dev/null 2>&1; then
  JOBS="$(sysctl -n hw.logicalcpu)"
else
  JOBS=2
fi

MAJOR_PY="$(echo "$PYTHON_VERSION" | cut -d. -f1)"
MINOR_PY="$(echo "$PYTHON_VERSION" | cut -d. -f2)"

# Relocatable RPATH settings
if [[ "$RUNNER_OS" == "Darwin" || "$RUNNER_OS" == "macOS" ]]; then
  export CFLAGS="-O3 -pipe"
  export LDFLAGS="-Wl,-dead_strip -Wl,-rpath,@executable_path/../lib"
elif [[ "$RUNNER_OS" == "Linux" ]]; then
  export CFLAGS="-O3 -pipe"
  export LDFLAGS="-Wl,--strip-all"
fi

# Allow skipping PGO/LTO via env for rapid local prototyping; CI always enables both.
OPT_FLAGS=()
if [[ "${PY_ENABLE_OPTIMIZATIONS:-1}" == "1" ]]; then
  OPT_FLAGS+=(--enable-optimizations --with-lto)
fi

echo "Configuring Python..."
./configure \
  --with-openssl="${BORINGSSL_INSTALL_DIR}" \
  --with-builtin-hashlib-hashes=sha3,blake2 \
  --with-ssl-default-suites=openssl \
  --prefix="${INSTALL_DIR}" \
  --enable-shared \
  --with-ensurepip=upgrade \
  ${OPT_FLAGS[@]+"${OPT_FLAGS[@]}"} \
  --disable-test-modules \
  --without-doc-strings || {
    echo "Configure failed. Showing config.log tail:"
    tail -n 120 config.log
    exit 1
  }

echo "Compiling Python with ${JOBS} jobs..."
make -j"${JOBS}"

echo "Installing Python..."
make altinstall
make bininstall

# Ensure convenient python/python3 and pip/pip3 symlinks
cd "${INSTALL_DIR}/bin"
if [[ ! -e python && -e python3 ]]; then
  ln -sf python3 python
fi
if [[ ! -e pip && -e pip3 ]]; then
  ln -sf pip3 pip
fi

# Strip binary to reduce package size
strip python3 || true

# On Linux, ensure all shared libraries have RPATH removed for StaticX compatibility
if [[ "$RUNNER_OS" == "Linux" ]]; then
  if command -v patchelf >/dev/null 2>&1; then
    echo "Running patchelf --remove-rpath on all compiled shared libraries..."
    find "${INSTALL_DIR}" -type f \( -name "*.so" -o -name "*.so.*" \) -exec patchelf --remove-rpath {} + 2>/dev/null || true
  fi
fi

# On macOS, fix dylib install name and executable references to use @rpath for full relocatability
if [[ "$RUNNER_OS" == "Darwin" || "$RUNNER_OS" == "macOS" ]]; then
  MAJOR_MINOR="${MAJOR_PY}.${MINOR_PY}"
  DYLIB_NAME="libpython${MAJOR_MINOR}.dylib"
  if [[ -f "${INSTALL_DIR}/lib/${DYLIB_NAME}" ]]; then
    install_name_tool -id "@rpath/${DYLIB_NAME}" "${INSTALL_DIR}/lib/${DYLIB_NAME}" || true
    install_name_tool -change "${INSTALL_DIR}/lib/${DYLIB_NAME}" "@rpath/${DYLIB_NAME}" "${INSTALL_DIR}/bin/python3" || true
    install_name_tool -change "${INSTALL_DIR}/lib/${DYLIB_NAME}" "@rpath/${DYLIB_NAME}" "${INSTALL_DIR}/bin/python${MAJOR_MINOR}" || true
  fi
fi

echo "Python compilation and installation completed successfully."
