# Builds Cosmos Depths into dist/cosmos-depths/:
#   cosmos.dll (cargo, release) + cosmos-depths.exe (MSVC, raylib static)
#   + steam_api64.dll when vendor/steam has one, + README.
# Usage: powershell -ExecutionPolicy Bypass -File examples\cosmos-depths\build.ps1 [-SteamDir DIR]
param([string]$SteamDir = '')
$ErrorActionPreference = 'Stop'
$demo = $PSScriptRoot
$repo = (Resolve-Path (Join-Path $demo '..\..')).Path
$dist = Join-Path $repo 'dist\cosmos-depths'
$obj = Join-Path $repo 'target\cosmos-depths-obj'
if (-not $SteamDir) { $SteamDir = Join-Path $repo 'vendor\steam' }

& (Join-Path $demo 'fetch-raylib.ps1')

# cosmos.dll (2 jobs: more runs out of memory here).
$env:CARGO_BUILD_JOBS = '2'
Push-Location $repo
try {
    cargo build --release -p cosmos-ffi
    if ($LASTEXITCODE -ne 0) { throw 'cargo build failed' }
} finally { Pop-Location }

# MSVC: cl is not on PATH; vswhere finds Visual Studio, vcvars64 sets it up.
$vsInstaller = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
$vs = & (Join-Path $vsInstaller 'vswhere.exe') -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'no Visual Studio with the x64 C++ tools found' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'

New-Item -ItemType Directory -Force $dist, $obj | Out-Null
$rl = Join-Path $demo 'vendor\raylib'
$cl = "cl /nologo /O2 /W4 /WX /MD /D_CRT_SECURE_NO_WARNINGS /I `"$repo\include`" /I `"$rl\include`" `"$demo\src\*.c`" /Fo`"$obj\\`" /Fe`"$dist\cosmos-depths.exe`"" +
      " /link `"$repo\target\release\cosmos.dll.lib`" `"$rl\lib\raylib.lib`" opengl32.lib gdi32.lib winmm.lib user32.lib shell32.lib"
$bat = Join-Path $obj 'build.bat'
Set-Content -Encoding ascii $bat "@echo off`r`nset `"PATH=%PATH%;$vsInstaller`"`r`ncall `"$vcvars`" >nul || exit /b 1`r`n$cl`r`n"
cmd /c "`"$bat`""
if ($LASTEXITCODE -ne 0) { throw 'cl failed' }

Copy-Item -Force (Join-Path $repo 'target\release\cosmos.dll') $dist
Copy-Item -Force (Join-Path $demo 'README.md') $dist
Copy-Item -Force (Join-Path $rl 'LICENSE') (Join-Path $dist 'raylib-LICENSE.txt')
$steam = Join-Path $SteamDir 'steam_api64.dll'
if (Test-Path $steam) { Copy-Item -Force $steam $dist; Write-Host 'steam_api64.dll included (Steam path on)' }
else { Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $dist 'steam_api64.dll') }
Write-Host "built $dist\cosmos-depths.exe"
