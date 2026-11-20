# build_python.ps1 - Windows CPython build statically linked against BoringSSL
param(
    [Parameter(Mandatory=$true)][string]$PythonVersion,
    [Parameter(Mandatory=$true)][string]$BoringSSLVersion,
    [Parameter(Mandatory=$true)][string]$BoringSSLInstallDir,
    [Parameter(Mandatory=$true)][string]$SourceDir,
    [Parameter(Mandatory=$true)][string]$InstallDir,
    [string]$Arch = "x64"
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================="
Write-Host "Building Python $PythonVersion with BoringSSL $BoringSSLVersion for Windows ($Arch)"
Write-Host "BoringSSL Install: $BoringSSLInstallDir"
Write-Host "Python Source:     $SourceDir"
Write-Host "Python Install:    $InstallDir"
Write-Host "=================================================="

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir

New-Item -ItemType Directory -Force -Path $SourceDir | Out-Null
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

if (-not (Test-Path "$SourceDir\PCBuild\build.bat")) {
    Write-Host "Cloning CPython source..."
    git clone --depth 1 --branch "v$PythonVersion" https://github.com/python/cpython.git $SourceDir
    if ($LASTEXITCODE -ne 0) {
        git clone --filter=blob:none https://github.com/python/cpython.git $SourceDir
        Set-Location $SourceDir
        git checkout $PythonVersion
    } else {
        Set-Location $SourceDir
    }
} else {
    Set-Location $SourceDir
}

# Dynamically probe BoringSSL HEAD and patch CPython
$resolvedBoringSSL = (Resolve-Path $BoringSSLInstallDir).Path
$patchScript = Join-Path $scriptDir "patch_cpython.py"
Write-Host "Running dynamic BoringSSL compatibility patcher: $patchScript"
$pyHost = if (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" } else { "python" }
& $pyHost $patchScript --boringssl-dir $resolvedBoringSSL --cpython-dir $SourceDir
if ($LASTEXITCODE -ne 0) {
    throw "patch_cpython.py failed with exit code $LASTEXITCODE"
}

# Update PCbuild\python.props for Visual Studio 2026 compatibility if needed.
if (Test-Path "PCbuild\python.props") {
    $propsPath = "PCbuild\python.props"
    $propsContent = Get-Content $propsPath -Raw
    if ($propsContent -match "'\$\(VisualStudioVersion\)' == '18\.0'>v143<") {
        Write-Host "Updating PCbuild\python.props for VS 2026 (v143 -> v145)..."
        $propsContent = $propsContent.Replace("'`$(VisualStudioVersion)' == '18.0'>v143<", "'`$(VisualStudioVersion)' == '18.0'>v145<")
        Set-Content -Path $propsPath -Value $propsContent -Encoding utf8
    }
}

# 1. Fetch externals excluding OpenSSL (we provide our own freshly built BoringSSL)
Write-Host "Fetching external dependencies (excluding OpenSSL)..."
& PCBuild\get_externals.bat --no-openssl
if ($LASTEXITCODE -ne 0) {
    throw "PCBuild\get_externals.bat failed with exit code $LASTEXITCODE"
}

# Determine architecture strings
if ($Arch -eq "arm64" -or $Arch -eq "ARM64") {
    $osslSub = "arm64"
    $buildArch = "ARM64"
} else {
    $osslSub = "amd64"
    $buildArch = "x64"
}

# 2. Configure MSBuild to point at our custom BoringSSL via CPython's native ExternalProps hook
$propsSrc = (Resolve-Path (Join-Path $repoRoot "patches\windows\boringssl.props")).Path

$env:BoringSSLInstallDir = $resolvedBoringSSL
$env:ExternalProps = $propsSrc

# 3. Locate Visual Studio installation and MSBuild
$vsPath = $env:VSINSTALLDIR
if (-not $vsPath -or -not (Test-Path $vsPath)) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        $vswhere = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
    }
    if (Test-Path $vswhere) {
        $vsPath = (& $vswhere -latest -products * -property installationPath).Trim()
    }
}
if (-not $vsPath -and $env:MSBUILD -and (Test-Path $env:MSBUILD)) {
    $vsPath = (Get-Item $env:MSBUILD).Directory.Parent.Parent.Parent.FullName
}

$msBuildArch = if ($Arch -ieq "arm64") { "arm64" } else { "amd64" }
if ($vsPath) {
    $candidate = Join-Path $vsPath "MSBuild\Current\Bin\$msBuildArch\MSBuild.exe"
    if (Test-Path $candidate) {
        $env:MSBUILD = $candidate
    } elseif (-not $env:MSBUILD -or -not (Test-Path $env:MSBUILD)) {
        $candidate = Join-Path $vsPath "MSBuild\Current\Bin\MSBuild.exe"
        if (Test-Path $candidate) {
            $env:MSBUILD = $candidate
        }
    }
}
if ($env:MSBUILD -and (Test-Path $env:MSBUILD)) {
    Write-Host "Using MSBuild: $env:MSBUILD"
    $msbDir = Split-Path -Parent $env:MSBUILD
    $env:PATH = "$msbDir;$env:PATH"
}

# Detect installed MSVC toolsets (e.g. v145 on VS 2026, v143 on VS 2022)
$selectedToolset = $null
if ($vsPath -and (Test-Path $vsPath)) {
    $foundToolsets = @()
    $toolsetDirs = Get-ChildItem -Path "$vsPath\MSBuild\Microsoft\VC" -Recurse -Depth 4 -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Parent.Name -eq "PlatformToolsets" } | Select-Object -ExpandProperty Name -Unique
    if ($toolsetDirs) { $foundToolsets += $toolsetDirs }

    $msvcDir = Join-Path $vsPath "VC\Tools\MSVC"
    if (Test-Path $msvcDir) {
        foreach ($d in (Get-ChildItem -Path $msvcDir -Directory -ErrorAction SilentlyContinue)) {
            if ($d.Name -match "^14\.5") { $foundToolsets += "v145" }
            elseif ($d.Name -match "^14\.4") { $foundToolsets += "v144" }
            elseif ($d.Name -match "^14\.3") { $foundToolsets += "v143" }
        }
    }
    $foundToolsets = $foundToolsets | Select-Object -Unique
    Write-Host "Found available MSVC toolsets: $($foundToolsets -join ', ')"

    $hasV143 = $foundToolsets -contains "v143"
    if ($env:VisualStudioVersion -eq "18.0" -or $vsPath -match "[\\/]18[\\/]") {
        if ($foundToolsets -contains "v145") {
            $selectedToolset = "v145"
        } elseif ($foundToolsets -contains "v144") {
            $selectedToolset = "v144"
        } elseif (-not $hasV143) {
            $selectedToolset = "v145"
        }
    } elseif (-not $hasV143 -and $foundToolsets.Count -gt 0) {
        $selectedToolset = $foundToolsets[0]
    }
}

# 4. Configure MSBuild response file PCbuild\msbuild.rsp
$preferredArch = if ($Arch -ieq "arm64") { "arm64" } else { "x64" }
$env:PreferredToolArchitecture = $preferredArch

$rspLines = @(
    "/p:ExternalProps=`"$propsSrc`"",
    "/p:BoringSSLInstallDir=`"$resolvedBoringSSL`"",
    "/p:PreferredToolArchitecture=$preferredArch",
    "/p:SkipCopySSLDLL=true"
)
$env:SkipCopySSLDLL = "true"

if ($selectedToolset) {
    Write-Host "Setting MSBuild PlatformToolset to: $selectedToolset"
    $rspLines += "/p:PlatformToolset=$selectedToolset"
}

Set-Content -Path "PCbuild\msbuild.rsp" -Value $rspLines -Encoding ASCII
Write-Host "Configured MSBuild response file PCbuild\msbuild.rsp with properties:"
$rspLines | ForEach-Object { Write-Host "  $_" }

# 5. Build Python
$extraBuildArgs = @(
    "`"/p:PreferredToolArchitecture=$preferredArch`""
)
if ($selectedToolset) {
    $extraBuildArgs += "`"/p:PlatformToolset=$selectedToolset`""
}

Write-Host "Building Python for $buildArch..."
if ($buildArch -eq "ARM64") {
    & PCBuild\build.bat -c Release -p $buildArch @extraBuildArgs
} else {
    & PCBuild\build.bat -c Release -p $buildArch --pgo @extraBuildArgs
}
if ($LASTEXITCODE -ne 0) {
    throw "PCBuild\build.bat failed with exit code $LASTEXITCODE"
}

# 6. Layout Python into clean installation directory
Write-Host "Creating layout into $InstallDir..."
if (Test-Path "PCBuild\python.bat") {
    & PCBuild\python.bat PC\layout --precompile --preset-default --copy $InstallDir
} elseif (Test-Path ".\python.bat") {
    & .\python.bat PC\layout --precompile --preset-default --copy $InstallDir
} else {
    $pyExe = Join-Path $SourceDir "PCbuild\$osslSub\python.exe"
    & $pyExe PC\layout --precompile --preset-default --copy $InstallDir
}

Write-Host "Python compilation and layout completed successfully."
