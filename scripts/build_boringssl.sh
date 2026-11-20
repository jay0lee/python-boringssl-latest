#!/usr/bin/env bash
set -euo pipefail

# build_boringssl.sh - Builds BoringSSL (static, PIC, Release) for CPython linking
# Usage: ./scripts/build_boringssl.sh <git_ref> <source_dir> <install_dir>
#   <git_ref> can be "main", "HEAD", a commit SHA, or a release tag (e.g. 0.20261105.0).

BORINGSSL_REF="${1:-main}"
SOURCE_DIR="${2:-}"
INSTALL_DIR="${3:-}"

if [[ -z "$SOURCE_DIR" || -z "$INSTALL_DIR" ]]; then
  echo "Usage: $0 <git_ref> <source_dir> <install_dir>" >&2
  exit 1
fi

echo "=================================================="
echo "Building BoringSSL (${BORINGSSL_REF})"
echo "Source:  ${SOURCE_DIR}"
echo "Install: ${INSTALL_DIR}"
echo "=================================================="

RUNNER_OS="${RUNNER_OS:-$(uname -s)}"
RUNNER_ARCH="${RUNNER_ARCH:-$(uname -m)}"

mkdir -p "$SOURCE_DIR" "$INSTALL_DIR"

if [[ ! -f "${SOURCE_DIR}/CMakeLists.txt" ]]; then
  echo "Cloning BoringSSL source..."
  if [[ "$BORINGSSL_REF" == "main" || "$BORINGSSL_REF" == "HEAD" ]]; then
    git clone --depth 1 https://github.com/google/boringssl.git "$SOURCE_DIR"
    cd "$SOURCE_DIR"
  else
    git clone --filter=blob:none https://github.com/google/boringssl.git "$SOURCE_DIR"
    cd "$SOURCE_DIR"
    git checkout "$BORINGSSL_REF"
  fi
else
  cd "$SOURCE_DIR"
  if [[ "$BORINGSSL_REF" != "HEAD" ]]; then
    git checkout "$BORINGSSL_REF" 2>/dev/null || true
  fi
fi

COMMIT_SHA="$(git rev-parse HEAD)"
SHORT_SHA="$(git rev-parse --short=12 HEAD)"
COMMIT_DATE="$(git show -s --format=%cI HEAD)"
COMMIT_DAY="$(git show -s --format=%cd --date=format:%Y%m%d HEAD)"
echo "Resolved BoringSSL commit: ${COMMIT_SHA} (${COMMIT_DATE})"

# Detect parallel jobs
if command -v nproc >/dev/null 2>&1; then
  JOBS="$(nproc)"
elif command -v sysctl >/dev/null 2>&1; then
  JOBS="$(sysctl -n hw.logicalcpu)"
else
  JOBS=2
fi

BUILD_DIR="${SOURCE_DIR}/build-release"
rm -rf "$BUILD_DIR"

CMAKE_GENERATOR_ARGS=()
if command -v ninja >/dev/null 2>&1; then
  CMAKE_GENERATOR_ARGS=(-G Ninja)
fi

CMAKE_EXTRA_ARGS=()
if [[ "$RUNNER_OS" == "Darwin" || "$RUNNER_OS" == "macOS" ]]; then
  CMAKE_EXTRA_ARGS+=(-DCMAKE_C_FLAGS_RELEASE="-O3 -DNDEBUG" -DCMAKE_CXX_FLAGS_RELEASE="-O3 -DNDEBUG")
else
  CMAKE_EXTRA_ARGS+=(-DCMAKE_C_FLAGS_RELEASE="-O3 -DNDEBUG" -DCMAKE_CXX_FLAGS_RELEASE="-O3 -DNDEBUG")
fi

echo "Configuring BoringSSL with CMake..."
cmake ${CMAKE_GENERATOR_ARGS[@]+"${CMAKE_GENERATOR_ARGS[@]}"} \
  -S "$SOURCE_DIR" \
  -B "$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_TESTING=OFF \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DCMAKE_INSTALL_LIBDIR=lib \
  ${CMAKE_EXTRA_ARGS[@]+"${CMAKE_EXTRA_ARGS[@]}"}

echo "Compiling BoringSSL with ${JOBS} jobs..."
cmake --build "$BUILD_DIR" --target crypto ssl bssl --parallel "${JOBS}"

echo "Installing BoringSSL headers, static libraries, and bssl CLI..."
cmake --install "$BUILD_DIR"

# Strip bssl CLI binary to reduce bundle size
if [[ -f "${INSTALL_DIR}/bin/bssl" ]]; then
  strip "${INSTALL_DIR}/bin/bssl" || true
fi

# Copy system CA certificates into BoringSSL's cert directory as standalone files
mkdir -p "${INSTALL_DIR}/ssl" "${INSTALL_DIR}/certs"
for ca in "/etc/ssl/cert.pem" "/etc/ssl/certs/ca-certificates.crt" "/etc/pki/tls/certs/ca-bundle.crt"; do
  if [[ -f "$ca" ]]; then
    cp -L -f "$ca" "${INSTALL_DIR}/ssl/cert.pem" || cp -f "$ca" "${INSTALL_DIR}/ssl/cert.pem"
    cp -L -f "$ca" "${INSTALL_DIR}/cert.pem" || cp -f "$ca" "${INSTALL_DIR}/cert.pem"
    break
  fi
done

# Extract BORINGSSL_API_VERSION from installed base.h
API_VER="$(grep -E '^#define BORINGSSL_API_VERSION ' "${INSTALL_DIR}/include/openssl/base.h" | awk '{print $3}' || echo 'unknown')"

# Write machine-readable metadata for build_info.py and validate_runtime.py
cat > "${INSTALL_DIR}/BORINGSSL_METADATA.json" <<EOF
{
  "version": "${COMMIT_DAY}-${SHORT_SHA}",
  "ref": "${BORINGSSL_REF}",
  "commit_sha": "${COMMIT_SHA}",
  "short_sha": "${SHORT_SHA}",
  "commit_date": "${COMMIT_DATE}",
  "api_version": "${API_VER}",
  "build_type": "Release (static, PIC, BUILD_TESTING=OFF)",
  "platform": "${RUNNER_OS} (${RUNNER_ARCH})",
  "compiler": "${CC:-$(command -v cc || echo cc)}"
}
EOF

echo "BoringSSL build completed successfully."
ls -lh "${INSTALL_DIR}/lib/" "${INSTALL_DIR}/bin/"
