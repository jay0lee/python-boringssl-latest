# build_boringssl.ps1 - Builds BoringSSL (static, Release, Ninja+MSVC) for Windows x64/arm64
param(
    [string]$BoringSSLRef = "main",
    [Parameter(Mandatory=$true)][string]$SourceDir,
    [Parameter(Mandatory=$true)][string]$InstallDir,
    [string]$Arch = "x64"
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================="
Write-Host "Building BoringSSL ($BoringSSLRef) for Windows ($Arch)"
Write-Host "Source:  $SourceDir"
Write-Host "Install: $InstallDir"
Write-Host "=================================================="

New-Item -ItemType Directory -Force -Path $SourceDir | Out-Null
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

if (-not (Test-Path "$SourceDir\CMakeLists.txt")) {
    Write-Host "Cloning BoringSSL source..."
    if ($BoringSSLRef -eq "main" -or $BoringSSLRef -eq "HEAD") {
        git clone --depth 1 https://github.com/google/boringssl.git $SourceDir
        Set-Location $SourceDir
    } else {
        git clone --filter=blob:none https://github.com/google/boringssl.git $SourceDir
        Set-Location $SourceDir
        git checkout $BoringSSLRef
    }
} else {
    Set-Location $SourceDir
    if ($BoringSSLRef -ne "HEAD") {
        git checkout $BoringSSLRef 2>$null
    }
}

$commitSha = (git rev-parse HEAD).Trim()
$shortSha = (git rev-parse --short=12 HEAD).Trim()
$commitDate = (git show -s --format=%cI HEAD).Trim()
$commitDay = (git show -s --format=%cd --date=format:%Y%m%d HEAD).Trim()
Write-Host "Resolved BoringSSL commit: $commitSha ($commitDate)"

# Rename conflicting GNU link if in MSYS/Git bash path
if (Test-Path "C:\Program Files\Git\usr\bin\link.exe") {
    Rename-Item -Path "C:\Program Files\Git\usr\bin\link.exe" -NewName "gnulink.exe" -Force -ErrorAction SilentlyContinue
}

$buildDir = Join-Path $SourceDir "build-release"
if (Test-Path $buildDir) {
    Remove-Item -Recurse -Force $buildDir
}

# BoringSSL BUILDING.md requires Ninja on Windows (Visual Studio generator does not assemble ASM files).
# Note: Do not set CMAKE_MSVC_RUNTIME_LIBRARY globally; CMake Release already defaults to /MD
# and setting it globally fails CMake's ASM language check on Windows ARM64.
$cmakeArgs = @(
    "-G", "Ninja",
    "-S", $SourceDir,
    "-B", $buildDir,
    "-DCMAKE_BUILD_TYPE=Release",
    "-DBUILD_SHARED_LIBS=OFF",
    "-DBUILD_TESTING=OFF",
    "-DCMAKE_INSTALL_PREFIX=$InstallDir",
    "-DCMAKE_INSTALL_LIBDIR=lib"
)

if ($Arch -ieq "arm64") {
    # BoringSSL's ARM64 .S files use Clang/GAS syntax rather than MSVC armasm64, and
    # CMake's enable_language(ASM) with cl.exe fails on MSVC_RUNTIME_LIBRARY.
    $cmakeArgs += "-DCMAKE_SYSTEM_PROCESSOR=ARM64"
    $cmakeArgs += "-DOPENSSL_NO_ASM=ON"
}

Write-Host "Configuring BoringSSL with CMake + Ninja..."
& cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) {
    throw "CMake configure failed with exit code $LASTEXITCODE"
}

Write-Host "Compiling BoringSSL (crypto, ssl, bssl)..."
& cmake --build $buildDir --target crypto ssl bssl --parallel
if ($LASTEXITCODE -ne 0) {
    throw "BoringSSL build failed with exit code $LASTEXITCODE"
}

Write-Host "Installing BoringSSL headers, static libraries, and bssl CLI..."
& cmake --install $buildDir
if ($LASTEXITCODE -ne 0) {
    throw "BoringSSL install failed with exit code $LASTEXITCODE"
}

# CPython's PCbuild/openssl.props expects libcrypto.lib and libssl.lib; CMake installs crypto.lib and ssl.lib
$libDir = Join-Path $InstallDir "lib"
if ((Test-Path "$libDir\crypto.lib") -and -not (Test-Path "$libDir\libcrypto.lib")) {
    Copy-Item -Path "$libDir\crypto.lib" -Destination "$libDir\libcrypto.lib" -Force
}
if ((Test-Path "$libDir\ssl.lib") -and -not (Test-Path "$libDir\libssl.lib")) {
    Copy-Item -Path "$libDir\ssl.lib" -Destination "$libDir\libssl.lib" -Force
}

# Extract BORINGSSL_API_VERSION from installed base.h
$apiVer = "unknown"
$baseH = Join-Path $InstallDir "include\openssl\base.h"
if (Test-Path $baseH) {
    $m = Select-String -Path $baseH -Pattern '^#define BORINGSSL_API_VERSION (\d+)' | Select-Object -First 1
    if ($m) { $apiVer = $m.Matches[0].Groups[1].Value }
}

$metadata = @{
    version     = "$commitDay-$shortSha"
    ref         = $BoringSSLRef
    commit_sha  = $commitSha
    short_sha   = $shortSha
    commit_date = $commitDate
    api_version = $apiVer
    build_type  = "Release (static, Ninja+MSVC, /MD, BUILD_TESTING=OFF)"
    platform    = "Windows ($Arch)"
    compiler    = "MSVC"
} | ConvertTo-Json -Depth 4
[System.IO.File]::WriteAllText((Join-Path $InstallDir "BORINGSSL_METADATA.json"), $metadata, [System.Text.Encoding]::UTF8)

Write-Host "BoringSSL build completed successfully."
Get-ChildItem "$InstallDir\lib", "$InstallDir\bin" -ErrorAction SilentlyContinue
