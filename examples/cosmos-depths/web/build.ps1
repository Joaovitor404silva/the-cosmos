# Builds the browser version of Cosmos Depths into dist/cosmos-depths-web/:
#   index.html + cosmos-depths.js/.wasm (emscripten, pthreads) + cosmos-web.js
#   (Nostr/WebRTC backend bundle) + coi-serviceworker.js (COOP/COEP on
#   static hosts such as GitHub Pages, so threads get SharedArrayBuffer).
# Needs: emsdk in .tools/emsdk (repo root), Node.js (npm).
# Usage: powershell -ExecutionPolicy Bypass -File examples\cosmos-depths\web\build.ps1
$ErrorActionPreference = 'Stop'
$web = $PSScriptRoot
$demo = (Resolve-Path (Join-Path $web '..')).Path
$repo = (Resolve-Path (Join-Path $demo '..\..')).Path
$emsdk = Join-Path $repo '.tools\emsdk'
$emcc = Join-Path $emsdk 'upstream\emscripten\emcc.exe'
if (-not (Test-Path $emcc)) { throw "no emcc at $emcc (install emsdk there)" }
$env:EM_CONFIG = Join-Path $emsdk '.emscripten'
$dist = Join-Path $repo 'dist\cosmos-depths-web'
$obj = Join-Path $repo 'target\cosmos-depths-web-obj'
New-Item -ItemType Directory -Force $dist, $obj | Out-Null

# raylib source (zlib licence), built with -pthread like the rest.
$Version = '5.5'
$Sha256 = '00e8a7c85f7a5221e56ee8e4e1c6642b773eae73d29379a91c8ac5149e803f42'
$rl = Join-Path $demo 'vendor\raylib-src'
if (-not (Test-Path (Join-Path $rl 'src\raylib.h'))) {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "cosmos-raylib-src-$PID"
    New-Item -ItemType Directory -Force $tmp | Out-Null
    try {
        $zip = Join-Path $tmp 'raylib.zip'
        Invoke-WebRequest -UseBasicParsing "https://github.com/raysan5/raylib/archive/refs/tags/$Version.zip" -OutFile $zip
        $got = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
        if ($got -ne $Sha256) { throw "raylib source zip hash mismatch: $got" }
        Expand-Archive $zip -DestinationPath $tmp -Force
        New-Item -ItemType Directory -Force $rl | Out-Null
        Copy-Item -Recurse -Force (Join-Path $tmp "raylib-$Version\*") $rl
    } finally {
        Remove-Item -Recurse -Force $tmp
    }
}

# JetBrains Mono (SIL OFL 1.1): raylib's default font is a tiny pixel font.
$fonts = Join-Path $demo 'vendor\fonts'
$font = Join-Path $fonts 'JetBrainsMono-Regular.ttf'
$fontLicense = Join-Path $fonts 'JetBrainsMono-OFL.txt'
foreach ($f in @(@($font, 'fonts/ttf/JetBrainsMono-Regular.ttf', 'a0bf60ef0f83c5ed4d7a75d45838548b1f6873372dfac88f71804491898d138f'),
                 @($fontLicense, 'OFL.txt', '30f0c136e3c88e422d0791acd97238870f9054a9729bc34cf2ff0d4ed8cac4ad'))) {
    if (Test-Path $f[0]) { continue }
    New-Item -ItemType Directory -Force $fonts | Out-Null
    Invoke-WebRequest -UseBasicParsing "https://raw.githubusercontent.com/JetBrains/JetBrainsMono/v2.304/$($f[1])" -OutFile "$($f[0]).part"
    $got = (Get-FileHash -Algorithm SHA256 "$($f[0]).part").Hash.ToLower()
    if ($got -ne $f[2]) { Remove-Item "$($f[0]).part"; throw "font download hash mismatch: $got" }
    Move-Item -Force "$($f[0]).part" $f[0]
}

function emcc { & $emcc @args; if ($LASTEXITCODE -ne 0) { throw "emcc failed: $args" } }

# NDEBUG + prefix map: no asserts, and no local paths in the published wasm.
$flags = @('-O2', '-pthread', '-DNDEBUG', "-ffile-prefix-map=$repo=.", "-fdebug-prefix-map=$repo=.")
$rlLib = Join-Path $obj 'libraylib.a'
if (-not (Test-Path $rlLib)) {
    $objs = @()
    foreach ($m in 'rcore', 'rshapes', 'rtextures', 'rtext', 'utils') {
        $o = Join-Path $obj "$m.o"
        emcc @flags -c (Join-Path $rl "src\$m.c") -o $o -DPLATFORM_WEB -DGRAPHICS_API_OPENGL_ES2 -Wno-everything
        $objs += $o
    }
    & (Join-Path $emsdk 'upstream\emscripten\emar.exe') rcs $rlLib @objs
    if ($LASTEXITCODE -ne 0) { throw 'emar failed' }
}

# JS backend bundle.
Push-Location $web
try {
    if (-not (Test-Path 'node_modules')) { npm ci --silent; if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' } }
    npm run --silent bundle
    if ($LASTEXITCODE -ne 0) { throw 'bundle failed' }
} finally { Pop-Location }

$src = @('game.c', 'main.c', 'dungeon.c', 'selftest.c' | ForEach-Object { Join-Path $demo "src\$_" })
$src += Join-Path $web 'c\plat_web.c'
$src += Join-Path $web 'c\cosmos_web.c'
emcc @flags -Wall -Werror -Wno-unused-function `
    -I (Join-Path $repo 'include') -I (Join-Path $rl 'src') -I (Join-Path $demo 'src') `
    @src $rlLib -o (Join-Path $dist 'cosmos-depths.js') `
    --js-library (Join-Path $web 'c\library_cosmos.js') --embed-file "$font@/font.ttf" `
    -sUSE_GLFW=3 -sASYNCIFY -sPTHREAD_POOL_SIZE=6 -sINITIAL_MEMORY=128MB -sSTACK_SIZE=1MB `
    -sEXIT_RUNTIME=0 '-sENVIRONMENT=web,worker'

Copy-Item -Force (Join-Path $web 'build\cosmos-web.js') $dist
Copy-Item -Force (Join-Path $web 'node_modules\coi-serviceworker\coi-serviceworker.min.js') (Join-Path $dist 'coi-serviceworker.js')
Copy-Item -Force (Join-Path $web 'shell.html') (Join-Path $dist 'index.html')
Copy-Item -Force (Join-Path $rl 'LICENSE') (Join-Path $dist 'raylib-LICENSE.txt')
Copy-Item -Force $fontLicense (Join-Path $dist 'JetBrainsMono-OFL.txt')
Write-Host "built $dist"
