# Downloads the official prebuilt raylib (MSVC x64) into vendor/raylib.
# raylib is zlib-licensed (see vendor/raylib/LICENSE after the download).
$ErrorActionPreference = 'Stop'
$Version = '5.5'
$Sha256  = '8d046084d12353183e701ef4c9d276c21fcd3243c2a368091fabfb2769b8507c'
$name = "raylib-${Version}_win64_msvc16"
$dest = Join-Path $PSScriptRoot 'vendor\raylib'
if (Test-Path (Join-Path $dest 'lib\raylib.lib')) { return }
$tmp = Join-Path ([IO.Path]::GetTempPath()) "cosmos-depths-raylib-$PID"
New-Item -ItemType Directory -Force $tmp | Out-Null
try {
    $zip = Join-Path $tmp "$name.zip"
    Invoke-WebRequest -UseBasicParsing "https://github.com/raysan5/raylib/releases/download/$Version/$name.zip" -OutFile $zip
    $got = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
    if ($got -ne $Sha256) { throw "raylib zip hash mismatch: $got" }
    Expand-Archive $zip -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Force $dest | Out-Null
    Copy-Item -Recurse -Force (Join-Path $tmp "$name\*") $dest
} finally {
    Remove-Item -Recurse -Force $tmp
}
